use axum::{
    Json, Router,
    body::Body,
    extract::{Path, Query, Request, State as AxumState},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use http_body_util::BodyExt;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::AppState;
use crate::api::notify::{kind, notify_user};
use crate::auth::{Headers, SendFileClaims};
use crate::db::models::Send;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/sends", get(list_sends).post(post_send))
        .route(
            "/api/sends/{uuid}",
            get(get_send).put(put_send).delete(delete_send),
        )
        .route("/api/sends/{uuid}/remove-password", post(remove_password))
        .route("/api/sends/access/{access_id}", post(public_access))
        .route("/api/sends/file/v2", post(post_file_send))
        .route("/api/sends/file", post(post_file_send))
        .route("/api/sends/{uuid}/file/{file_id}", post(upload_file_send))
        .route("/api/sends/access/file/{access_id}/{file_id}", post(public_access_file_init))
        .route("/api/sends/{access_id}/access/file/{file_id}", post(public_access_file_init))
        .route("/api/sends/{uuid}/{file_id}", get(public_access_file_download))
}

fn err_json(code: StatusCode, msg: &str) -> Response {
    (code, Json(json!({ "ErrorModel": { "Message": msg }, "Object": "error", "Message": msg })))
        .into_response()
}

const SEND_TYPE_TEXT: i32 = 0;

#[derive(Deserialize)]
struct SendBody {
    name: String,
    #[serde(default)]
    notes: Option<String>,
    #[serde(rename = "type")]
    atype: i32,
    text: Option<Value>,
    file: Option<Value>,
    key: String,
    #[serde(rename = "deletionDate")]
    deletion_date: String,
    #[serde(default, rename = "expirationDate")]
    expiration_date: Option<String>,
    #[serde(default)]
    password: Option<String>,
    #[serde(default, rename = "maxAccessCount")]
    max_access_count: Option<i32>,
    #[serde(default, rename = "hideEmail")]
    hide_email: Option<bool>,
    #[serde(default)]
    disabled: Option<bool>,
}

fn data_text(body: &SendBody) -> Result<String, Response> {
    let v = match body.atype {
        0 => body.text.clone().ok_or_else(|| err_json(StatusCode::BAD_REQUEST, "text payload required"))?,
        1 => body
            .file
            .clone()
            .ok_or_else(|| err_json(StatusCode::BAD_REQUEST, "file payload required (file sends not yet supported)"))?,
        _ => return Err(err_json(StatusCode::BAD_REQUEST, "unknown send type")),
    };
    serde_json::to_string(&v).map_err(|_| err_json(StatusCode::BAD_REQUEST, "failed to serialize data"))
}

pub(crate) fn send_json(s: &Send) -> Value {
    let parsed_data: Value = serde_json::from_str(&s.data).unwrap_or(Value::Null);
    let (text, file) = if s.atype == 0 {
        (parsed_data.clone(), Value::Null)
    } else {
        // Bitwarden clients read lowercase `id` / `size` / `sizeName` /
        // `fileName`. Older rows we wrote stored capitalised keys; project
        // both casings so existing sends keep working without a migration.
        let mut file = parsed_data.clone();
        if let Value::Object(ref mut map) = file {
            for (cap, lower) in
                [("Id", "id"), ("Size", "size"), ("SizeName", "sizeName"), ("FileName", "fileName")]
            {
                if !map.contains_key(lower)
                    && let Some(v) = map.get(cap).cloned()
                {
                    map.insert(lower.into(), v);
                }
            }
        }
        (Value::Null, file)
    };
    json!({
        "Object": "send",
        "Id": s.uuid,
        "AccessId": s.uuid,
        "Type": s.atype,
        "Name": s.name,
        "Notes": s.notes,
        "Text": text,
        "File": file,
        "Key": s.akey,
        "MaxAccessCount": s.max_access_count,
        "AccessCount": s.access_count,
        "Password": if s.password_hash.is_empty() { Value::Null } else { Value::String("present".into()) },
        "Disabled": s.disabled == 1,
        "HideEmail": s.hide_email.map(|v| v == 1).unwrap_or(false),
        "RevisionDate": s.revision_date,
        "DeletionDate": s.deletion_date,
        "ExpirationDate": s.expiration_date,
    })
}

async fn load_owned(state: &AppState, headers: &Headers, uuid: &str) -> Result<Send, Response> {
    let s = Send::find_by_uuid(&state.db, uuid)
        .await
        .map_err(|_| err_json(StatusCode::INTERNAL_SERVER_ERROR, "database error"))?
        .ok_or_else(|| err_json(StatusCode::NOT_FOUND, "Send not found"))?;
    if s.user_uuid.as_deref() != Some(headers.user.uuid.as_str()) {
        return Err(err_json(StatusCode::NOT_FOUND, "Send not found"));
    }
    Ok(s)
}

#[worker::send]
async fn list_sends(AxumState(state): AxumState<AppState>, headers: Headers) -> Response {
    let sends = match Send::find_by_user(&state.db, &headers.user.uuid).await {
        Ok(s) => s,
        Err(_) => return err_json(StatusCode::INTERNAL_SERVER_ERROR, "database error"),
    };
    let data: Vec<Value> = sends.iter().map(send_json).collect();
    Json(json!({ "Object": "list", "Data": data, "ContinuationToken": Value::Null })).into_response()
}

#[worker::send]
async fn post_send(
    AxumState(state): AxumState<AppState>,
    headers: Headers,
    Json(body): Json<SendBody>,
) -> Response {
    if body.atype != SEND_TYPE_TEXT {
        return err_json(StatusCode::BAD_REQUEST, "Only text sends are supported on this endpoint");
    }
    let data = match data_text(&body) {
        Ok(d) => d,
        Err(e) => return e,
    };
    let mut send = Send::new(body.atype, body.name, data, body.key, body.deletion_date);
    send.user_uuid = Some(headers.user.uuid.clone());
    send.notes = body.notes;
    send.expiration_date = body.expiration_date;
    send.max_access_count = body.max_access_count;
    send.hide_email = body.hide_email.map(|b| if b { 1 } else { 0 });
    send.disabled = body.disabled.map(|b| if b { 1 } else { 0 }).unwrap_or(0);
    if let Some(pw) = body.password.as_deref().filter(|s| !s.is_empty()) {
        apply_send_password(&mut send, pw);
    }
    if send.save(&state.db).await.is_err() {
        return err_json(StatusCode::INTERNAL_SERVER_ERROR, "failed to save send");
    }
    notify_user(&state, &headers.user.uuid, kind::SYNC_SEND_CREATE, &send.uuid).await;
    Json(send_json(&send)).into_response()
}

#[worker::send]
async fn get_send(
    AxumState(state): AxumState<AppState>,
    headers: Headers,
    Path(uuid): Path<String>,
) -> Response {
    let s = match load_owned(&state, &headers, &uuid).await {
        Ok(s) => s,
        Err(e) => return e,
    };
    Json(send_json(&s)).into_response()
}

#[worker::send]
async fn put_send(
    AxumState(state): AxumState<AppState>,
    headers: Headers,
    Path(uuid): Path<String>,
    Json(body): Json<SendBody>,
) -> Response {
    let mut s = match load_owned(&state, &headers, &uuid).await {
        Ok(s) => s,
        Err(e) => return e,
    };
    if body.atype != s.atype {
        return err_json(StatusCode::BAD_REQUEST, "send type cannot change");
    }
    let data = match data_text(&body) {
        Ok(d) => d,
        Err(e) => return e,
    };
    s.name = body.name;
    s.notes = body.notes;
    s.data = data;
    s.akey = body.key;
    s.deletion_date = body.deletion_date;
    s.expiration_date = body.expiration_date;
    s.max_access_count = body.max_access_count;
    s.hide_email = body.hide_email.map(|b| if b { 1 } else { 0 });
    if let Some(d) = body.disabled {
        s.disabled = if d { 1 } else { 0 };
    }
    if let Some(pw) = body.password.as_deref().filter(|p| !p.is_empty()) {
        apply_send_password(&mut s, pw);
    }
    s.revision_date = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Micros, true);
    if s.save(&state.db).await.is_err() {
        return err_json(StatusCode::INTERNAL_SERVER_ERROR, "failed to save send");
    }
    notify_user(&state, &headers.user.uuid, kind::SYNC_SEND_UPDATE, &s.uuid).await;
    Json(send_json(&s)).into_response()
}

#[worker::send]
async fn delete_send(
    AxumState(state): AxumState<AppState>,
    headers: Headers,
    Path(uuid): Path<String>,
) -> Response {
    let s = match load_owned(&state, &headers, &uuid).await {
        Ok(s) => s,
        Err(e) => return e,
    };
    let send_uuid = s.uuid.clone();
    let was_file_send = s.atype == 1;
    if s.delete(&state.db).await.is_err() {
        return err_json(StatusCode::INTERNAL_SERVER_ERROR, "failed to delete send");
    }
    // Best-effort R2 cleanup. We delete the prefix folder by listing the keys
    // since file sends store under {uuid}/{file_id}.
    if was_file_send {
        let prefix = format!("{send_uuid}/");
        if let Ok(list) = state.sends.list().prefix(prefix).execute().await {
            for obj in list.objects() {
                let _r2 = state.sends.delete(obj.key()).await;
            }
        }
    }
    notify_user(&state, &headers.user.uuid, kind::SYNC_SEND_DELETE, &send_uuid).await;
    Json(json!({})).into_response()
}

#[worker::send]
async fn remove_password(
    AxumState(state): AxumState<AppState>,
    headers: Headers,
    Path(uuid): Path<String>,
) -> Response {
    let mut s = match load_owned(&state, &headers, &uuid).await {
        Ok(s) => s,
        Err(e) => return e,
    };
    s.password_hash.clear();
    s.password_salt.clear();
    s.password_iter = None;
    if s.save(&state.db).await.is_err() {
        return err_json(StatusCode::INTERNAL_SERVER_ERROR, "failed to save send");
    }
    notify_user(&state, &headers.user.uuid, kind::SYNC_SEND_UPDATE, &s.uuid).await;
    Json(send_json(&s)).into_response()
}

#[allow(dead_code)]
#[derive(Deserialize)]
struct AccessBody {
    #[serde(default)]
    password: Option<String>,
}

#[worker::send]
async fn public_access(
    AxumState(state): AxumState<AppState>,
    Path(access_id): Path<String>,
    Json(body): Json<AccessBody>,
) -> Response {
    // Rate-limit anonymous access attempts per send id so a hostile peer
    // can't brute-force a Send password without anyone noticing.
    if !crate::ratelimit::check(
        &state.ratelimit_kv,
        &crate::ratelimit::LOGIN_LIMIT,
        &access_id,
    )
    .await
    {
        return err_json(StatusCode::TOO_MANY_REQUESTS, "Too many access attempts");
    }
    let mut s = match Send::find_by_uuid(&state.db, &access_id).await {
        Ok(Some(s)) => s,
        _ => return err_json(StatusCode::NOT_FOUND, "Send not found"),
    };
    if s.disabled == 1 {
        return err_json(StatusCode::NOT_FOUND, "Send disabled");
    }
    let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Micros, true);
    if s.deletion_date <= now {
        return err_json(StatusCode::NOT_FOUND, "Send expired");
    }
    if let Some(max) = s.max_access_count
        && s.access_count >= max
    {
        return err_json(StatusCode::NOT_FOUND, "Send access limit reached");
    }
    if !verify_send_password(&s, body.password.as_deref()) {
        // Mirror upstream's response: 401 with a stable error key so the client
        // re-prompts for the password rather than treating it as "not found".
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "Object": "error", "Message": "Invalid password.", "ErrorModel": { "Message": "Invalid password." } })),
        )
            .into_response();
    }
    s.access_count += 1;
    let _result = s.save(&state.db).await;

    let parsed_data: Value = serde_json::from_str(&s.data).unwrap_or(Value::Null);
    // Bitwarden's public-access shape splits text vs file by the send's
    // type. Type 0 = text → put data under `Text`. Type 1 = file → put it
    // under `File` and project capitalised legacy keys to lowercase so
    // `send.file.id` resolves on every client.
    let (text, file) = if s.atype == 0 {
        (parsed_data, Value::Null)
    } else {
        let mut file = parsed_data;
        if let Value::Object(ref mut map) = file {
            for (cap, lower) in
                [("Id", "id"), ("Size", "size"), ("SizeName", "sizeName"), ("FileName", "fileName")]
            {
                if !map.contains_key(lower)
                    && let Some(v) = map.get(cap).cloned()
                {
                    map.insert(lower.into(), v);
                }
            }
        }
        (Value::Null, file)
    };
    Json(json!({
        "Object": "send-access",
        "Id": s.uuid,
        "Type": s.atype,
        "Name": s.name,
        "Text": text,
        "File": file,
        "ExpirationDate": s.expiration_date,
        "CreatorIdentifier": Value::Null,
    }))
    .into_response()
}

// ---------------------------------------------------------------------------
// File sends.
//
// Storage layout: R2 bucket SENDS, key `{send_uuid}/{file_id}`. The download
// URL (`/api/sends/{uuid}/{file_id}?t=jwt`) is anonymous + time-bound; the
// JWT is signed with the same RSA key used for login JWTs and carries a
// dedicated issuer suffix `|send_file`.

#[derive(Deserialize)]
struct FileSendBody {
    name: String,
    #[serde(default)]
    notes: Option<String>,
    file: Value,
    #[serde(rename = "fileLength", default)]
    file_length: Option<i64>,
    key: String,
    #[serde(rename = "deletionDate")]
    deletion_date: String,
    #[serde(default, rename = "expirationDate")]
    expiration_date: Option<String>,
    #[serde(default)]
    password: Option<String>,
    #[serde(default, rename = "maxAccessCount")]
    max_access_count: Option<i32>,
    #[serde(default, rename = "hideEmail")]
    hide_email: Option<bool>,
    #[serde(default)]
    disabled: Option<bool>,
}

const MAX_FILE_SEND_BYTES: usize = 100 * 1024 * 1024; // 100 MiB

#[worker::send]
async fn post_file_send(
    AxumState(state): AxumState<AppState>,
    headers: Headers,
    Json(body): Json<FileSendBody>,
) -> Response {
    let file_id = uuid::Uuid::new_v4().simple().to_string();
    let mut data = body.file.clone();
    if let Value::Object(ref mut map) = data {
        // Bitwarden's send-file model uses lowercase keys (`id`, `size`,
        // `sizeName`). The client reads `send.file.id` and posts to
        // `/api/sends/{uuid}/file/{id}`; if we wrote the canonical-cased
        // `Id` only, the client gets `undefined` and the upload (and
        // later download) URL is `/file/undefined`.
        map.insert("id".into(), Value::String(file_id.clone()));
        if let Some(len) = body.file_length {
            map.insert("size".into(), Value::String(len.to_string()));
            map.insert("sizeName".into(), Value::String(format_size(len)));
        }
    }
    let data_str = serde_json::to_string(&data).unwrap_or_else(|_| "{}".into());

    let mut send = Send::new(1, body.name, data_str, body.key, body.deletion_date.clone());
    send.user_uuid = Some(headers.user.uuid.clone());
    send.notes = body.notes;
    send.expiration_date = body.expiration_date;
    send.max_access_count = body.max_access_count;
    send.hide_email = body.hide_email.map(|b| if b { 1 } else { 0 });
    send.disabled = body.disabled.map(|b| if b { 1 } else { 0 }).unwrap_or(0);
    if let Some(pw) = body.password.as_deref().filter(|s| !s.is_empty()) {
        apply_send_password(&mut send, pw);
    }
    if send.save(&state.db).await.is_err() {
        return err_json(StatusCode::INTERNAL_SERVER_ERROR, "failed to save send");
    }

    let host = state.env_var("DOMAIN").unwrap_or_default();
    let upload_url = format!("{host}/api/sends/{}/file/{}", send.uuid, file_id);
    notify_user(&state, &headers.user.uuid, kind::SYNC_SEND_CREATE, &send.uuid).await;

    Json(json!({
        "Object": "send-fileUpload",
        "FileUploadType": 0,
        "Url": upload_url,
        "SendResponse": send_json(&send),
    }))
    .into_response()
}

fn format_size(bytes: i64) -> String {
    const KB: f64 = 1024.0;
    let n = bytes as f64;
    if n < KB {
        format!("{bytes} Bytes")
    } else if n < KB * KB {
        format!("{:.1} KB", n / KB)
    } else if n < KB * KB * KB {
        format!("{:.1} MB", n / (KB * KB))
    } else {
        format!("{:.2} GB", n / (KB * KB * KB))
    }
}

#[worker::send]
async fn upload_file_send(
    AxumState(state): AxumState<AppState>,
    headers: Headers,
    Path((send_uuid, file_id)): Path<(String, String)>,
    request: Request,
) -> Response {
    let send = match Send::find_by_uuid(&state.db, &send_uuid).await {
        Ok(Some(s)) if s.user_uuid.as_deref() == Some(headers.user.uuid.as_str()) => s,
        _ => return err_json(StatusCode::NOT_FOUND, "Send not found"),
    };
    if send.atype != 1 {
        return err_json(StatusCode::BAD_REQUEST, "Send is not a file send");
    }

    // Bitwarden's clients post `multipart/form-data` with the encrypted
    // payload under the `data` part. If we wrote the raw body verbatim,
    // the download would surface the multipart envelope and clients would
    // fail to decrypt. Pull the `data` part out before persisting.
    let content_type = request
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned)
        .unwrap_or_default();

    let body_bytes = match request.into_body().collect().await {
        Ok(b) => b.to_bytes(),
        Err(_) => return err_json(StatusCode::BAD_REQUEST, "failed to read body"),
    };

    let bytes: Vec<u8> = if let Some(boundary) = parse_multipart_boundary(&content_type) {
        match extract_multipart_part(&body_bytes, &boundary, "data") {
            Some(b) => b,
            None => return err_json(StatusCode::BAD_REQUEST, "missing `data` part in multipart body"),
        }
    } else {
        // Fallback: some older clients PUT the raw bytes. Accept that too.
        body_bytes.to_vec()
    };

    if bytes.is_empty() || bytes.len() > MAX_FILE_SEND_BYTES {
        return err_json(StatusCode::BAD_REQUEST, "Invalid upload size");
    }
    let key = format!("{}/{}", send.uuid, file_id);
    if state.sends.put(key, bytes).execute().await.is_err() {
        return err_json(StatusCode::INTERNAL_SERVER_ERROR, "R2 upload failed");
    }
    notify_user(&state, &headers.user.uuid, kind::SYNC_SEND_UPDATE, &send.uuid).await;
    Json(json!({})).into_response()
}

/// Parse the boundary out of a `multipart/form-data; boundary=...` header.
pub(crate) fn parse_multipart_boundary(content_type: &str) -> Option<String> {
    if !content_type.to_ascii_lowercase().contains("multipart/form-data") {
        return None;
    }
    for piece in content_type.split(';') {
        let trimmed = piece.trim();
        if let Some(rest) = trimmed.strip_prefix("boundary=") {
            // RFC 7578: boundary may be quoted.
            return Some(rest.trim_matches('"').to_owned());
        }
    }
    None
}

/// Extract the body of the named multipart part. Returns the raw bytes of
/// the `data` segment without the part headers or trailing CRLF.
pub(crate) fn extract_multipart_part(body: &[u8], boundary: &str, part_name: &str) -> Option<Vec<u8>> {
    let delim = format!("--{boundary}");
    let delim_bytes = delim.as_bytes();
    // Walk the body finding each `--<boundary>` separator. Between each pair
    // is one part: headers \r\n\r\n <bytes> \r\n.
    let mut cursor = find_subsequence(body, delim_bytes)?;
    while let Some(part_start) = find_subsequence(&body[cursor..], delim_bytes) {
        let abs_part_start = cursor + part_start + delim_bytes.len();
        // The two bytes after the boundary tell us if this is the closing
        // boundary (`--`) or another part (`\r\n`).
        if abs_part_start + 2 > body.len() {
            return None;
        }
        if &body[abs_part_start..abs_part_start + 2] == b"--" {
            return None;
        }
        // Skip the trailing CRLF after the boundary.
        let header_start = abs_part_start + 2;
        // Find the blank line that ends the part headers.
        let header_end = find_subsequence(&body[header_start..], b"\r\n\r\n")?;
        let payload_start = header_start + header_end + 4;
        let headers = std::str::from_utf8(&body[header_start..header_start + header_end]).ok()?;

        let next_delim = find_subsequence(&body[payload_start..], delim_bytes)?;
        let mut payload_end = payload_start + next_delim;
        // Strip the CRLF that precedes the next boundary.
        if payload_end >= 2 && &body[payload_end - 2..payload_end] == b"\r\n" {
            payload_end -= 2;
        }

        if part_matches_name(headers, part_name) {
            return Some(body[payload_start..payload_end].to_vec());
        }
        cursor = payload_end;
    }
    None
}

fn part_matches_name(headers: &str, part_name: &str) -> bool {
    for line in headers.split("\r\n") {
        let lower = line.to_ascii_lowercase();
        if let Some(rest) = lower.strip_prefix("content-disposition:")
            && rest.contains("form-data")
        {
            let needle = format!("name=\"{}\"", part_name.to_ascii_lowercase());
            return lower.contains(&needle);
        }
    }
    false
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

#[allow(dead_code)]
#[derive(Deserialize)]
struct PublicAccessFileBody {
    #[serde(default)]
    password: Option<String>,
}

#[worker::send]
async fn public_access_file_init(
    AxumState(state): AxumState<AppState>,
    Path((access_id, file_id)): Path<(String, String)>,
    Json(body): Json<PublicAccessFileBody>,
) -> Response {
    if !crate::ratelimit::check(
        &state.ratelimit_kv,
        &crate::ratelimit::LOGIN_LIMIT,
        &access_id,
    )
    .await
    {
        return err_json(StatusCode::TOO_MANY_REQUESTS, "Too many access attempts");
    }
    let mut s = match Send::find_by_uuid(&state.db, &access_id).await {
        Ok(Some(s)) => s,
        _ => return err_json(StatusCode::NOT_FOUND, "Send not found"),
    };
    if s.disabled == 1 || s.atype != 1 {
        return err_json(StatusCode::NOT_FOUND, "Send not available");
    }
    let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Micros, true);
    if s.deletion_date <= now {
        return err_json(StatusCode::NOT_FOUND, "Send expired");
    }
    if let Some(max) = s.max_access_count
        && s.access_count >= max
    {
        return err_json(StatusCode::NOT_FOUND, "Send access limit reached");
    }
    if !verify_send_password(&s, body.password.as_deref()) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "Object": "error", "Message": "Invalid password.", "ErrorModel": { "Message": "Invalid password." } })),
        )
            .into_response();
    }
    s.access_count += 1;
    let _save = s.save(&state.db).await;

    // Mint a short-lived download URL.
    let exp = match chrono::DateTime::parse_from_rfc3339(&s.deletion_date) {
        Ok(d) => d.with_timezone(&chrono::Utc),
        Err(_) => chrono::Utc::now() + chrono::Duration::hours(1),
    };
    let claims = SendFileClaims::new(&state.keys, s.uuid.clone(), file_id.clone(), exp);
    let token = match state.keys.encode(&claims) {
        Ok(t) => t,
        Err(_) => return err_json(StatusCode::INTERNAL_SERVER_ERROR, "jwt encode failed"),
    };
    let host = state.env_var("DOMAIN").unwrap_or_default();
    let url = format!("{host}/api/sends/{}/{}?t={token}", s.uuid, file_id);

    let parsed_data: Value = serde_json::from_str(&s.data).unwrap_or(Value::Null);
    Json(json!({
        "Object": "send-fileAccess",
        "Id": s.uuid,
        "Type": s.atype,
        "Name": s.name,
        "File": parsed_data,
        "ExpirationDate": s.expiration_date,
        "Url": url,
    }))
    .into_response()
}

#[derive(Deserialize)]
struct DownloadQuery {
    #[serde(default)]
    t: Option<String>,
}

#[worker::send]
async fn public_access_file_download(
    AxumState(state): AxumState<AppState>,
    Path((send_uuid, file_id)): Path<(String, String)>,
    Query(q): Query<DownloadQuery>,
) -> Response {
    let token = match q.t {
        Some(t) if !t.is_empty() => t,
        _ => return err_json(StatusCode::FORBIDDEN, "Token required"),
    };
    let issuer = SendFileClaims::issuer(&state.keys);
    let claims: SendFileClaims = match state.keys.decode(&token, &issuer) {
        Ok(c) => c,
        Err(_) => return err_json(StatusCode::FORBIDDEN, "Invalid token"),
    };
    if claims.sub != send_uuid || claims.fid != file_id {
        return err_json(StatusCode::FORBIDDEN, "Token doesn't match path");
    }
    let key = format!("{send_uuid}/{file_id}");
    let obj = match state.sends.get(&key).execute().await {
        Ok(Some(o)) => o,
        Ok(None) => return err_json(StatusCode::NOT_FOUND, "File missing from storage"),
        Err(_) => return err_json(StatusCode::INTERNAL_SERVER_ERROR, "R2 read failed"),
    };
    let bytes = match obj.body() {
        Some(b) => match b.bytes().await {
            Ok(v) => v,
            Err(_) => return err_json(StatusCode::INTERNAL_SERVER_ERROR, "R2 stream failed"),
        },
        None => Vec::new(),
    };
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .header(header::CONTENT_LENGTH, bytes.len().to_string())
        .body(Body::from(bytes))
        .unwrap_or_else(|_| err_json(StatusCode::INTERNAL_SERVER_ERROR, "response build failed"))
}

const SEND_PW_ITERATIONS: u32 = 100_000;

fn random_salt(len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    let _ = getrandom::getrandom(&mut buf);
    buf
}

/// Hash and persist a send password. Uses the same PBKDF2 helper as user
/// passwords so a single primitive covers both.
fn apply_send_password(send: &mut Send, password: &str) {
    let salt = random_salt(64);
    let hash = crate::crypto::hash_password(password.as_bytes(), &salt, SEND_PW_ITERATIONS);
    send.password_salt = salt;
    send.password_hash = hash;
    send.password_iter = Some(SEND_PW_ITERATIONS as i32);
}

/// Verify a supplied password against the stored hash. Returns true if the
/// send has no password (no challenge needed) or the supplied password matches.
fn verify_send_password(send: &Send, supplied: Option<&str>) -> bool {
    if send.password_hash.is_empty() {
        return true;
    }
    let Some(pw) = supplied.filter(|s| !s.is_empty()) else {
        return false;
    };
    let iter = send.password_iter.unwrap_or(SEND_PW_ITERATIONS as i32) as u32;
    crate::crypto::verify_password_hash(pw.as_bytes(), &send.password_salt, &send.password_hash, iter)
}
