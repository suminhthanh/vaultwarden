use axum::{
    Json, Router,
    body::Body,
    extract::{Path, Request, State as AxumState},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use http_body_util::BodyExt;
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::AppState;
use crate::api::ciphers::cipher_to_json;
use crate::auth::Headers;
use crate::db::models::{Attachment, Cipher, Favorite};

pub fn routes() -> Router<AppState> {
    Router::new()
        .route(
            "/api/ciphers/{cipher_id}/attachment/v2",
            post(post_attachment_v2),
        )
        .route(
            "/api/ciphers/{cipher_id}/attachment",
            post(post_attachment_v2),
        )
        .route(
            "/api/ciphers/{cipher_id}/attachment-admin",
            post(post_attachment_v2),
        )
        .route(
            "/api/ciphers/{cipher_id}/attachment/{attachment_id}",
            post(upload_attachment).get(get_attachment).delete(delete_attachment),
        )
        .route(
            "/api/ciphers/{cipher_id}/attachment/{attachment_id}/admin",
            post(upload_attachment).get(get_attachment).delete(delete_attachment),
        )
        .route(
            "/api/ciphers/{cipher_id}/attachment/{attachment_id}/delete",
            post(delete_attachment).put(delete_attachment),
        )
        .route(
            "/api/ciphers/{cipher_id}/attachment/{attachment_id}/delete-admin",
            post(delete_attachment).put(delete_attachment),
        )
        .route(
            "/api/ciphers/{cipher_id}/attachment/{attachment_id}/share",
            post(share_attachment),
        )
        .route(
            "/api/ciphers/{cipher_id}/attachment/{attachment_id}/file",
            get(download_attachment_file),
        )
        .route(
            "/api/attachments/{cipher_id}/{attachment_id}",
            get(download_attachment_file),
        )
}

fn err_json(code: StatusCode, msg: &str) -> Response {
    (code, Json(json!({ "ErrorModel": { "Message": msg }, "Object": "error", "Message": msg })))
        .into_response()
}

fn r2_key(cipher_id: &str, attachment_id: &str) -> String {
    format!("{cipher_id}/{attachment_id}")
}

pub(crate) fn attachment_json(state: &AppState, a: &Attachment) -> Value {
    let host = state.env_var("DOMAIN").unwrap_or_default();
    let url = format!("{host}/api/ciphers/{}/attachment/{}/file", a.cipher_uuid, a.id);
    json!({
        "Object": "attachment",
        "Id": a.id,
        "Url": url,
        "FileName": a.file_name,
        "Key": a.akey,
        "Size": a.file_size.to_string(),
        "SizeName": format_size(a.file_size as i64),
    })
}

fn format_size(bytes: i64) -> String {
    const KB: f64 = 1024.0;
    let n = bytes as f64;
    if n < KB { format!("{bytes} Bytes") }
    else if n < KB * KB { format!("{:.1} KB", n / KB) }
    else if n < KB * KB * KB { format!("{:.1} MB", n / (KB * KB)) }
    else { format!("{:.2} GB", n / (KB * KB * KB)) }
}

async fn load_owned_cipher(
    state: &AppState,
    headers: &Headers,
    cipher_id: &str,
) -> Result<Cipher, Response> {
    let cipher = Cipher::find_by_uuid(&state.db, cipher_id)
        .await
        .map_err(|_| err_json(StatusCode::INTERNAL_SERVER_ERROR, "database error"))?
        .ok_or_else(|| err_json(StatusCode::NOT_FOUND, "Cipher not found"))?;
    if cipher.user_uuid.as_deref() != Some(headers.user.uuid.as_str()) {
        return Err(err_json(StatusCode::NOT_FOUND, "Cipher not found"));
    }
    Ok(cipher)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AttachmentRequestData {
    key: String,
    file_name: String,
    file_size: Value,
    #[serde(default)]
    admin_request: Option<bool>,
}

fn parse_size(v: &Value) -> Option<i64> {
    v.as_i64().or_else(|| v.as_str().and_then(|s| s.parse().ok()))
}

#[worker::send]
async fn post_attachment_v2(
    AxumState(state): AxumState<AppState>,
    headers: Headers,
    Path(cipher_id): Path<String>,
    Json(body): Json<AttachmentRequestData>,
) -> Response {
    let cipher = match load_owned_cipher(&state, &headers, &cipher_id).await {
        Ok(c) => c,
        Err(e) => return e,
    };
    let Some(file_size_i64) = parse_size(&body.file_size) else {
        return err_json(StatusCode::BAD_REQUEST, "fileSize must be a number");
    };
    if file_size_i64 < 0 || file_size_i64 > i32::MAX as i64 {
        return err_json(StatusCode::BAD_REQUEST, "fileSize out of range");
    }
    let file_size = file_size_i64 as i32;

    let attachment_id = Uuid::new_v4().simple().to_string();
    let attachment = Attachment::new(
        attachment_id.clone(),
        cipher.uuid.clone(),
        body.file_name,
        file_size,
        Some(body.key),
    );
    if attachment.save(&state.db).await.is_err() {
        return err_json(StatusCode::INTERNAL_SERVER_ERROR, "failed to save attachment");
    }

    let host = state.env_var("DOMAIN").unwrap_or_default();
    let upload_url = format!("{host}/api/ciphers/{}/attachment/{}", cipher.uuid, attachment_id);
    let response_key = if body.admin_request.unwrap_or(false) { "cipherMiniResponse" } else { "cipherResponse" };
    let favorite = Favorite::is_favorite(&state.db, &headers.user.uuid, &cipher.uuid).await.unwrap_or(false);

    Json(json!({
        "Object": "attachment-fileUpload",
        "AttachmentId": attachment_id,
        "Url": upload_url,
        "FileUploadType": 0,
        response_key: cipher_to_json(&cipher, favorite),
    }))
    .into_response()
}

#[worker::send]
async fn upload_attachment(
    AxumState(state): AxumState<AppState>,
    headers: Headers,
    Path((cipher_id, attachment_id)): Path<(String, String)>,
    request: Request,
) -> Response {
    let cipher = match load_owned_cipher(&state, &headers, &cipher_id).await {
        Ok(c) => c,
        Err(e) => return e,
    };

    let Ok(Some(attachment)) = Attachment::find_by_id(&state.db, &attachment_id).await else {
        return err_json(StatusCode::NOT_FOUND, "Attachment not found");
    };
    if attachment.cipher_uuid != cipher.uuid {
        return err_json(StatusCode::NOT_FOUND, "Attachment doesn't belong to cipher");
    }

    let content_type = request
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned)
        .unwrap_or_default();
    let body_bytes = match request.into_body().collect().await {
        Ok(c) => c.to_bytes(),
        Err(_) => return err_json(StatusCode::BAD_REQUEST, "failed to read body"),
    };
    // Bitwarden clients post `multipart/form-data` with the encrypted blob
    // under the `data` part. If we wrote the raw body we'd persist the
    // multipart envelope and downloads would fail to decrypt. Pull just
    // the `data` payload out — same pattern as `sends::upload_file_send`.
    let bytes: Vec<u8> = if let Some(boundary) =
        crate::api::sends::parse_multipart_boundary(&content_type)
    {
        match crate::api::sends::extract_multipart_part(&body_bytes, &boundary, "data") {
            Some(b) => b,
            None => return err_json(StatusCode::BAD_REQUEST, "missing `data` part"),
        }
    } else {
        body_bytes.to_vec()
    };
    if (bytes.len() as i32) != attachment.file_size {
        return err_json(
            StatusCode::BAD_REQUEST,
            &format!("body size {} does not match declared {}", bytes.len(), attachment.file_size),
        );
    }
    let key = r2_key(&cipher.uuid, &attachment.id);
    if state.attachments.put(key, bytes).execute().await.is_err() {
        return err_json(StatusCode::INTERNAL_SERVER_ERROR, "failed to upload to R2");
    }
    crate::api::events::log_cipher_event(
        &state,
        crate::api::events::event_type::CIPHER_ATTACHMENT_CREATED,
        &cipher.uuid,
        &headers.user.uuid,
        cipher.organization_uuid.as_deref(),
        headers.device.atype,
    )
    .await;
    crate::api::notify::notify_user(
        &state,
        &headers.user.uuid,
        crate::api::notify::kind::SYNC_CIPHER_UPDATE,
        &cipher.uuid,
    )
    .await;
    if let Some(org_id) = cipher.organization_uuid.as_deref() {
        crate::api::notify::notify_org(
            &state,
            org_id,
            crate::api::notify::kind::SYNC_CIPHER_UPDATE,
            &cipher.uuid,
        )
        .await;
    }

    Json(json!({})).into_response()
}

#[worker::send]
async fn get_attachment(
    AxumState(state): AxumState<AppState>,
    headers: Headers,
    Path((cipher_id, attachment_id)): Path<(String, String)>,
) -> Response {
    let cipher = match load_owned_cipher(&state, &headers, &cipher_id).await {
        Ok(c) => c,
        Err(e) => return e,
    };
    let Ok(Some(attachment)) = Attachment::find_by_id(&state.db, &attachment_id).await else {
        return err_json(StatusCode::NOT_FOUND, "Attachment not found");
    };
    if attachment.cipher_uuid != cipher.uuid {
        return err_json(StatusCode::NOT_FOUND, "Attachment doesn't belong to cipher");
    }
    Json(attachment_json(&state, &attachment)).into_response()
}

#[worker::send]
async fn download_attachment_file(
    AxumState(state): AxumState<AppState>,
    headers: Headers,
    Path((cipher_id, attachment_id)): Path<(String, String)>,
) -> Response {
    let cipher = match load_owned_cipher(&state, &headers, &cipher_id).await {
        Ok(c) => c,
        Err(e) => return e,
    };
    let Ok(Some(attachment)) = Attachment::find_by_id(&state.db, &attachment_id).await else {
        return err_json(StatusCode::NOT_FOUND, "Attachment not found");
    };
    if attachment.cipher_uuid != cipher.uuid {
        return err_json(StatusCode::NOT_FOUND, "Attachment doesn't belong to cipher");
    }

    let key = r2_key(&cipher.uuid, &attachment.id);
    let obj = match state.attachments.get(key).execute().await {
        Ok(Some(o)) => o,
        Ok(None) => return err_json(StatusCode::NOT_FOUND, "File missing from storage"),
        Err(_) => return err_json(StatusCode::INTERNAL_SERVER_ERROR, "R2 read failed"),
    };
    let body_bytes = match obj.body() {
        Some(b) => match b.bytes().await {
            Ok(v) => v,
            Err(_) => return err_json(StatusCode::INTERNAL_SERVER_ERROR, "R2 stream failed"),
        },
        None => Vec::new(),
    };
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .header(header::CONTENT_LENGTH, body_bytes.len().to_string())
        .body(Body::from(body_bytes))
        .unwrap_or_else(|_| err_json(StatusCode::INTERNAL_SERVER_ERROR, "response build failed"))
}

#[worker::send]
async fn delete_attachment(
    AxumState(state): AxumState<AppState>,
    headers: Headers,
    Path((cipher_id, attachment_id)): Path<(String, String)>,
) -> Response {
    let cipher = match load_owned_cipher(&state, &headers, &cipher_id).await {
        Ok(c) => c,
        Err(e) => return e,
    };
    let Ok(Some(attachment)) = Attachment::find_by_id(&state.db, &attachment_id).await else {
        return err_json(StatusCode::NOT_FOUND, "Attachment not found");
    };
    if attachment.cipher_uuid != cipher.uuid {
        return err_json(StatusCode::NOT_FOUND, "Attachment doesn't belong to cipher");
    }
    let key = r2_key(&cipher.uuid, &attachment.id);
    let _result = state.attachments.delete(key).await;
    if attachment.delete(&state.db).await.is_err() {
        return err_json(StatusCode::INTERNAL_SERVER_ERROR, "failed to delete attachment row");
    }
    crate::api::events::log_cipher_event(
        &state,
        crate::api::events::event_type::CIPHER_ATTACHMENT_DELETED,
        &cipher.uuid,
        &headers.user.uuid,
        cipher.organization_uuid.as_deref(),
        headers.device.atype,
    )
    .await;
    crate::api::notify::notify_user(
        &state,
        &headers.user.uuid,
        crate::api::notify::kind::SYNC_CIPHER_UPDATE,
        &cipher.uuid,
    )
    .await;
    if let Some(org_id) = cipher.organization_uuid.as_deref() {
        crate::api::notify::notify_org(
            &state,
            org_id,
            crate::api::notify::kind::SYNC_CIPHER_UPDATE,
            &cipher.uuid,
        )
        .await;
    }
    Json(json!({})).into_response()
}

/// Re-key an existing attachment under a different cipher key when the cipher
/// is shared into an organization. We only persist the new wrapping key + name
/// — the bytes in R2 stay where they are. Mirrors upstream's
/// `/api/ciphers/{cipher_id}/attachment/{attachment_id}/share` shape.
#[derive(Deserialize)]
struct ShareAttachmentBody {
    #[serde(default, rename = "fileName", alias = "FileName")]
    file_name: Option<String>,
    #[serde(default, rename = "key", alias = "Key")]
    key: Option<String>,
}

#[worker::send]
async fn share_attachment(
    AxumState(state): AxumState<AppState>,
    headers: Headers,
    Path((cipher_id, attachment_id)): Path<(String, String)>,
    Json(body): Json<ShareAttachmentBody>,
) -> Response {
    let cipher = match load_owned_cipher(&state, &headers, &cipher_id).await {
        Ok(c) => c,
        Err(e) => return e,
    };
    let mut attachment = match Attachment::find_by_id(&state.db, &attachment_id).await {
        Ok(Some(a)) if a.cipher_uuid == cipher.uuid => a,
        _ => return err_json(StatusCode::NOT_FOUND, "Attachment not found"),
    };
    if let Some(name) = body.file_name {
        attachment.file_name = name;
    }
    if let Some(k) = body.key {
        attachment.akey = Some(k);
    }
    if attachment.save(&state.db).await.is_err() {
        return err_json(StatusCode::INTERNAL_SERVER_ERROR, "failed to save attachment");
    }
    crate::api::notify::notify_user(
        &state,
        &headers.user.uuid,
        crate::api::notify::kind::SYNC_CIPHER_UPDATE,
        &cipher.uuid,
    )
    .await;
    if let Some(org_id) = cipher.organization_uuid.as_deref() {
        crate::api::notify::notify_org(
            &state,
            org_id,
            crate::api::notify::kind::SYNC_CIPHER_UPDATE,
            &cipher.uuid,
        )
        .await;
    }
    Json(attachment_json(&state, &attachment)).into_response()
}
