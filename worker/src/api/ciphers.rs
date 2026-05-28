use axum::{
    Json, Router,
    extract::{Path, State as AxumState},
    http::StatusCode,
    response::IntoResponse,
    routing::{delete, get, post, put},
};
use chrono::{SecondsFormat, Utc};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::AppState;
use crate::api::notify::{kind, notify_user};
use crate::auth::Headers;
use crate::db::models::{Archive, CipherCollection, Cipher, Favorite, FolderCipher, Membership};

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/ciphers", get(list_ciphers).post(post_cipher))
        .route(
            "/api/ciphers/{uuid}",
            get(get_cipher).put(put_cipher).delete(delete_cipher_soft),
        )
        .route("/api/ciphers/{uuid}/details", get(get_cipher))
        .route("/api/ciphers/{uuid}/delete", put(delete_cipher_soft).post(delete_cipher_soft))
        .route("/api/ciphers/{uuid}/restore", put(restore_cipher).post(restore_cipher))
        .route("/api/ciphers/{uuid}/restore-admin", put(restore_cipher).post(restore_cipher))
        .route("/api/ciphers/{uuid}/delete-admin", delete(delete_cipher_hard).put(delete_cipher_soft).post(delete_cipher_soft))
        .route(
            "/api/ciphers/{uuid}/partial",
            put(put_cipher_partial).post(put_cipher_partial),
        )
        .route(
            "/api/ciphers/{uuid}/collections",
            put(put_cipher_collections).post(put_cipher_collections),
        )
        .route(
            "/api/ciphers/{uuid}/collections_v2",
            put(put_cipher_collections).post(put_cipher_collections),
        )
        .route(
            "/api/ciphers/{uuid}/collections-admin",
            put(put_cipher_collections).post(put_cipher_collections),
        )
        .route(
            "/api/ciphers/{uuid}/share",
            put(share_cipher).post(share_cipher),
        )
        .route("/api/ciphers/delete", put(bulk_delete_soft).post(bulk_delete_soft))
        .route("/api/ciphers/delete-admin", put(bulk_delete_soft).post(bulk_delete_soft))
        .route("/api/ciphers/restore", put(bulk_restore).post(bulk_restore))
        .route("/api/ciphers/restore-admin", put(bulk_restore).post(bulk_restore))
        .route("/api/ciphers/move", put(bulk_move).post(bulk_move))
        .route("/api/ciphers/share", put(bulk_share).post(bulk_share))
        .route("/api/ciphers/bulk-collections", put(bulk_collections).post(bulk_collections))
        .route("/api/ciphers/create", post(post_cipher))
        .route("/api/ciphers/purge", post(purge_user_ciphers))
        .route("/api/ciphers/import", post(import_ciphers))
        .route("/api/ciphers/import-organization", post(import_ciphers))
        .route("/api/ciphers/organization-details", get(list_org_ciphers))
        .route("/api/ciphers/{uuid}/archive", put(archive_cipher).post(archive_cipher))
        .route("/api/ciphers/{uuid}/unarchive", put(unarchive_cipher).post(unarchive_cipher))
        .route("/api/ciphers/archive", put(bulk_archive))
        .route("/api/ciphers/unarchive", put(bulk_unarchive))
        .route("/api/ciphers/{uuid}/admin", get(get_cipher).put(put_cipher).post(put_cipher).delete(delete_cipher_hard))
        .route("/api/ciphers/admin", post(post_cipher))
}

/// Wire shape for `/api/ciphers` POST/PUT bodies — Bitwarden client format.
#[allow(dead_code)]
#[derive(Deserialize)]
pub(crate) struct CipherData {
    #[serde(default, rename = "folderId", alias = "folder_id", alias = "folderID")]
    pub folder_id: Option<String>,
    #[serde(default, rename = "organizationId", alias = "organization_id", alias = "organizationID")]
    pub organization_id: Option<String>,
    #[serde(default, rename = "collectionIds", alias = "collection_ids", alias = "CollectionIds")]
    pub collection_ids: Option<Vec<String>>,
    #[serde(default)]
    pub key: Option<String>,
    #[serde(rename = "type")]
    pub atype: i32,
    pub name: String,
    #[serde(default)]
    pub notes: Option<String>,
    #[serde(default)]
    pub fields: Option<Value>,
    #[serde(default)]
    pub login: Option<Value>,
    #[serde(default, rename = "secureNote", alias = "secure_note")]
    pub secure_note: Option<Value>,
    #[serde(default)]
    pub card: Option<Value>,
    #[serde(default)]
    pub identity: Option<Value>,
    #[serde(default, rename = "sshKey", alias = "ssh_key")]
    pub ssh_key: Option<Value>,
    #[serde(default)]
    pub favorite: Option<bool>,
    #[serde(default)]
    pub reprompt: Option<i32>,
    #[serde(default, rename = "passwordHistory", alias = "password_history")]
    pub password_history: Option<Value>,
}

fn now_iso() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Micros, true)
}

fn err_json(code: StatusCode, msg: &str) -> (StatusCode, Json<Value>) {
    (code, Json(json!({ "ErrorModel": { "Message": msg }, "Object": "error", "Message": msg })))
}

/// Parses any string that already looks like a JSON value, otherwise wraps in null.
/// Upstream stores typed sub-objects (login, card, identity, …) plus password_history /
/// fields as JSON strings on the cipher row, then re-parses them on the way out.
/// For a given user, return the folder UUID a cipher is linked to (if any).
/// `folders_ciphers` is many-to-many globally, but Bitwarden semantics expect
/// at most one folder per `(cipher, user)`, so we filter to folders the user
/// actually owns.
async fn folder_for_user_cipher(
    state: &AppState,
    user_uuid: &str,
    cipher_uuid: &str,
) -> Option<String> {
    let folder_ids = FolderCipher::list_by_cipher(&state.db, cipher_uuid).await.ok()?;
    if folder_ids.is_empty() {
        return None;
    }
    let user_folders = crate::db::models::Folder::find_by_user(&state.db, user_uuid).await.ok()?;
    let owned: std::collections::HashSet<String> = user_folders.into_iter().map(|f| f.uuid).collect();
    folder_ids.into_iter().find(|id| owned.contains(id))
}

/// Replace the user's folder linkage for a cipher. Other users' linkages on
/// org-shared ciphers stay untouched.
async fn set_cipher_folder(
    state: &AppState,
    user_uuid: &str,
    cipher_uuid: &str,
    folder_id: Option<&str>,
) {
    if let (Ok(existing), Ok(user_folders)) = (
        FolderCipher::list_by_cipher(&state.db, cipher_uuid).await,
        crate::db::models::Folder::find_by_user(&state.db, user_uuid).await,
    ) {
        let owned: std::collections::HashSet<String> =
            user_folders.into_iter().map(|f| f.uuid).collect();
        for fid in existing.iter().filter(|id| owned.contains(id.as_str())) {
            let _result = FolderCipher::unset(&state.db, cipher_uuid, fid).await;
        }
    }
    if let Some(fid) = folder_id.filter(|s| !s.is_empty()) {
        let _result = FolderCipher::set(&state.db, cipher_uuid, fid).await;
    }
}

fn data_text_for(d: &CipherData) -> String {
    let v = match d.atype {
        1 => d.login.clone().unwrap_or(Value::Null),
        2 => d.secure_note.clone().unwrap_or(Value::Null),
        3 => d.card.clone().unwrap_or(Value::Null),
        4 => d.identity.clone().unwrap_or(Value::Null),
        5 => d.ssh_key.clone().unwrap_or(Value::Null),
        _ => Value::Null,
    };
    serde_json::to_string(&v).unwrap_or_else(|_| "{}".into())
}

fn parse_json_or_null(s: Option<&str>) -> Value {
    s.and_then(|s| serde_json::from_str::<Value>(s).ok()).unwrap_or(Value::Null)
}

pub(crate) fn cipher_to_json(c: &Cipher, favorite: bool) -> Value {
    cipher_to_json_full(c, favorite, &[], None)
}

#[allow(dead_code)]
pub(crate) fn cipher_to_json_with_collections(
    c: &Cipher,
    favorite: bool,
    collection_ids: &[String],
) -> Value {
    cipher_to_json_full(c, favorite, collection_ids, None)
}

pub(crate) fn cipher_to_json_with_folder(
    c: &Cipher,
    favorite: bool,
    collection_ids: &[String],
    folder_id: Option<&str>,
) -> Value {
    cipher_to_json_full(c, favorite, collection_ids, folder_id)
}

/// Same as `cipher_to_json_with_folder`, but also resolves the cipher's
/// attachments through R2 so the client gets a usable download URL each.
pub(crate) async fn cipher_to_json_with_attachments_and_folder(
    state: &AppState,
    c: &Cipher,
    favorite: bool,
    collection_ids: &[String],
    folder_id: Option<&str>,
) -> Value {
    cipher_to_json_with_attachments(state, c, favorite, collection_ids, folder_id).await
}

pub(crate) fn cipher_to_json_full(
    c: &Cipher,
    favorite: bool,
    collection_ids: &[String],
    folder_id: Option<&str>,
) -> Value {
    cipher_to_json_inner(c, favorite, collection_ids, folder_id, Value::Null)
}

/// Build the full cipher response with attachments resolved through R2's url
/// shape. Use this from handlers that have an AppState (sync, single-cipher
/// fetch) so the client gets an immediately-usable Url for each attachment.
pub(crate) async fn cipher_to_json_with_attachments(
    state: &AppState,
    c: &Cipher,
    favorite: bool,
    collection_ids: &[String],
    folder_id: Option<&str>,
) -> Value {
    use crate::db::models::Attachment;
    let attachments_value = match Attachment::find_by_cipher(&state.db, &c.uuid).await {
        Ok(rows) if !rows.is_empty() => Value::Array(
            rows.iter()
                .map(|a| crate::api::attachments::attachment_json(state, a))
                .collect(),
        ),
        _ => Value::Null,
    };
    cipher_to_json_inner(c, favorite, collection_ids, folder_id, attachments_value)
}

fn cipher_to_json_inner(
    c: &Cipher,
    favorite: bool,
    collection_ids: &[String],
    folder_id: Option<&str>,
    attachments: Value,
) -> Value {
    let data = parse_json_or_null(Some(c.data.as_str()));
    let fields = parse_json_or_null(c.fields.as_deref());
    let password_history = parse_json_or_null(c.password_history.as_deref());

    let (login, secure_note, card, identity, ssh_key) = match c.atype {
        1 => (data.clone(), Value::Null, Value::Null, Value::Null, Value::Null),
        2 => (Value::Null, data.clone(), Value::Null, Value::Null, Value::Null),
        3 => (Value::Null, Value::Null, data.clone(), Value::Null, Value::Null),
        4 => (Value::Null, Value::Null, Value::Null, data.clone(), Value::Null),
        5 => (Value::Null, Value::Null, Value::Null, Value::Null, data.clone()),
        _ => (Value::Null, Value::Null, Value::Null, Value::Null, Value::Null),
    };

    json!({
        "Object": "cipherDetails",
        "Id": c.uuid,
        "Type": c.atype,
        "Name": c.name,
        "Notes": c.notes,
        "Fields": fields,
        "Login": login,
        "SecureNote": secure_note,
        "Card": card,
        "Identity": identity,
        "SshKey": ssh_key,
        "Key": c.key,
        "FolderId": folder_id,
        "OrganizationId": c.organization_uuid,
        "OrganizationUseTotp": c.organization_uuid.is_some(),
        "Favorite": favorite,
        "Reprompt": c.reprompt.unwrap_or(0),
        "Edit": true,
        "ViewPassword": true,
        "Attachments": attachments,
        "PasswordHistory": password_history,
        "CollectionIds": collection_ids,
        "RevisionDate": c.updated_at,
        "CreationDate": c.created_at,
        "DeletedDate": c.deleted_at,
    })
}

#[worker::send]
async fn list_ciphers(
    AxumState(state): AxumState<AppState>,
    headers: Headers,
) -> impl IntoResponse {
    let ciphers = match Cipher::find_visible_to_user(&state.db, &headers.user.uuid).await {
        Ok(c) => c,
        Err(_) => return err_json(StatusCode::INTERNAL_SERVER_ERROR, "database error"),
    };
    let favorites: std::collections::HashSet<String> = Favorite::cipher_uuids_for_user(&state.db, &headers.user.uuid)
        .await
        .unwrap_or_default()
        .into_iter()
        .collect();
    let mut data = Vec::with_capacity(ciphers.len());
    for c in &ciphers {
        let coll_ids = if c.organization_uuid.is_some() {
            CipherCollection::list_by_cipher(&state.db, &c.uuid).await.unwrap_or_default()
        } else {
            Vec::new()
        };
        let folder = folder_for_user_cipher(&state, &headers.user.uuid, &c.uuid).await;
        data.push(
            cipher_to_json_with_attachments(
                &state,
                c,
                favorites.contains(&c.uuid),
                &coll_ids,
                folder.as_deref(),
            )
            .await,
        );
    }
    (
        StatusCode::OK,
        Json(json!({ "Object": "list", "Data": data, "ContinuationToken": Value::Null })),
    )
}

#[worker::send]
async fn post_cipher(
    AxumState(state): AxumState<AppState>,
    headers: Headers,
    Json(body): Json<CipherData>,
) -> impl IntoResponse {
    if let Some(org_id) = body.organization_id.as_deref() {
        // Caller must be a member of the org and the cipher must be linked to at
        // least one collection in that org.
        match Membership::find_by_user_and_org(&state.db, &headers.user.uuid, org_id).await {
            Ok(Some(_)) => (),
            _ => return err_json(StatusCode::NOT_FOUND, "Organization not found"),
        }
        if body.collection_ids.as_ref().map_or(true, |c| c.is_empty()) {
            return err_json(StatusCode::BAD_REQUEST, "collectionIds is required for org-owned ciphers");
        }
    }

    let mut cipher = Cipher::new(body.atype, body.name.clone());
    cipher.user_uuid = if body.organization_id.is_some() { None } else { Some(headers.user.uuid.clone()) };
    cipher.organization_uuid = body.organization_id.clone();
    cipher.key = body.key.clone();
    cipher.notes = body.notes.clone();
    cipher.fields = body.fields.as_ref().and_then(|v| serde_json::to_string(v).ok());
    cipher.password_history = body.password_history.as_ref().and_then(|v| serde_json::to_string(v).ok());
    cipher.reprompt = body.reprompt;
    cipher.data = data_text_for(&body);
    if cipher.save(&state.db).await.is_err() {
        return err_json(StatusCode::INTERNAL_SERVER_ERROR, "failed to save cipher");
    }

    let mut linked: Vec<String> = Vec::new();
    if let Some(coll_ids) = body.collection_ids.as_ref() {
        for cid in coll_ids {
            if CipherCollection::set(&state.db, &cipher.uuid, cid).await.is_ok() {
                linked.push(cid.clone());
            }
        }
    }

    let favorite = body.favorite.unwrap_or(false);
    if favorite && Favorite::set(&state.db, &headers.user.uuid, &cipher.uuid, true).await.is_err() {
        return err_json(StatusCode::INTERNAL_SERVER_ERROR, "failed to set favorite");
    }
    set_cipher_folder(&state, &headers.user.uuid, &cipher.uuid, body.folder_id.as_deref()).await;
    notify_user(&state, &headers.user.uuid, kind::SYNC_CIPHER_CREATE, &cipher.uuid).await;
    if let Some(org_id) = cipher.organization_uuid.as_deref() {
        crate::api::notify::notify_org(&state, org_id, kind::SYNC_CIPHER_CREATE, &cipher.uuid).await;
    }
    crate::api::events::log_cipher_event(
        &state,
        crate::api::events::event_type::CIPHER_CREATED,
        &cipher.uuid,
        &headers.user.uuid,
        cipher.organization_uuid.as_deref(),
        headers.device.atype,
    )
    .await;
    (StatusCode::OK, Json(cipher_to_json_with_folder(&cipher, favorite, &linked, body.folder_id.as_deref())))
}

async fn load_owned_cipher(
    state: &AppState,
    headers: &Headers,
    uuid: &str,
) -> Result<Cipher, (StatusCode, Json<Value>)> {
    let cipher = Cipher::find_by_uuid(&state.db, uuid)
        .await
        .map_err(|_| err_json(StatusCode::INTERNAL_SERVER_ERROR, "database error"))?
        .ok_or_else(|| err_json(StatusCode::NOT_FOUND, "Cipher not found"))?;

    // User-owned cipher: only the owner can read/write.
    if let Some(owner) = cipher.user_uuid.as_deref() {
        if owner == headers.user.uuid {
            return Ok(cipher);
        }
        return Err(err_json(StatusCode::NOT_FOUND, "Cipher not found"));
    }

    // Org-owned cipher: any active member of the org can read/write (no
    // per-collection ACLs yet — phase 5 follow-up).
    if let Some(org) = cipher.organization_uuid.as_deref()
        && Membership::find_by_user_and_org(&state.db, &headers.user.uuid, org)
            .await
            .map_err(|_| err_json(StatusCode::INTERNAL_SERVER_ERROR, "database error"))?
            .is_some()
    {
        return Ok(cipher);
    }

    Err(err_json(StatusCode::NOT_FOUND, "Cipher not found"))
}

#[worker::send]
async fn get_cipher(
    AxumState(state): AxumState<AppState>,
    headers: Headers,
    Path(uuid): Path<String>,
) -> impl IntoResponse {
    let cipher = match load_owned_cipher(&state, &headers, &uuid).await {
        Ok(c) => c,
        Err(e) => return e,
    };
    let favorite = Favorite::is_favorite(&state.db, &headers.user.uuid, &cipher.uuid).await.unwrap_or(false);
    let folder = folder_for_user_cipher(&state, &headers.user.uuid, &cipher.uuid).await;
    let coll_ids = if cipher.organization_uuid.is_some() {
        CipherCollection::list_by_cipher(&state.db, &cipher.uuid).await.unwrap_or_default()
    } else {
        Vec::new()
    };
    (
        StatusCode::OK,
        Json(cipher_to_json_with_attachments(&state, &cipher, favorite, &coll_ids, folder.as_deref()).await),
    )
}

#[worker::send]
async fn put_cipher(
    AxumState(state): AxumState<AppState>,
    headers: Headers,
    Path(uuid): Path<String>,
    Json(body): Json<CipherData>,
) -> impl IntoResponse {
    let mut cipher = match load_owned_cipher(&state, &headers, &uuid).await {
        Ok(c) => c,
        Err(e) => return e,
    };
    cipher.atype = body.atype;
    cipher.name = body.name.clone();
    cipher.notes = body.notes.clone();
    cipher.fields = body.fields.as_ref().and_then(|v| serde_json::to_string(v).ok());
    cipher.password_history = body.password_history.as_ref().and_then(|v| serde_json::to_string(v).ok());
    cipher.reprompt = body.reprompt;
    cipher.key = body.key.clone();
    cipher.data = data_text_for(&body);
    if cipher.save(&state.db).await.is_err() {
        return err_json(StatusCode::INTERNAL_SERVER_ERROR, "failed to save cipher");
    }
    if let Some(fav) = body.favorite {
        let _result = Favorite::set(&state.db, &headers.user.uuid, &cipher.uuid, fav).await;
    }
    // The PUT body always carries folderId — explicit null clears the folder.
    set_cipher_folder(&state, &headers.user.uuid, &cipher.uuid, body.folder_id.as_deref()).await;
    let favorite =
        Favorite::is_favorite(&state.db, &headers.user.uuid, &cipher.uuid).await.unwrap_or(false);
    let folder = folder_for_user_cipher(&state, &headers.user.uuid, &cipher.uuid).await;
    let coll_ids = if cipher.organization_uuid.is_some() {
        CipherCollection::list_by_cipher(&state.db, &cipher.uuid).await.unwrap_or_default()
    } else {
        Vec::new()
    };
    notify_user(&state, &headers.user.uuid, kind::SYNC_CIPHER_UPDATE, &cipher.uuid).await;
    // Fan out to every confirmed org member so co-owners see the change live.
    if let Some(org_id) = cipher.organization_uuid.as_deref() {
        crate::api::notify::notify_org(&state, org_id, kind::SYNC_CIPHER_UPDATE, &cipher.uuid).await;
    }
    crate::api::events::log_cipher_event(
        &state,
        crate::api::events::event_type::CIPHER_UPDATED,
        &cipher.uuid,
        &headers.user.uuid,
        cipher.organization_uuid.as_deref(),
        headers.device.atype,
    )
    .await;
    (StatusCode::OK, Json(cipher_to_json_with_folder(&cipher, favorite, &coll_ids, folder.as_deref())))
}

#[worker::send]
async fn delete_cipher_soft(
    AxumState(state): AxumState<AppState>,
    headers: Headers,
    Path(uuid): Path<String>,
) -> impl IntoResponse {
    let mut cipher = match load_owned_cipher(&state, &headers, &uuid).await {
        Ok(c) => c,
        Err(e) => return e,
    };
    cipher.deleted_at = Some(now_iso());
    if cipher.save(&state.db).await.is_err() {
        return err_json(StatusCode::INTERNAL_SERVER_ERROR, "failed to soft-delete cipher");
    }
    notify_user(&state, &headers.user.uuid, kind::SYNC_CIPHER_UPDATE, &cipher.uuid).await;
    if let Some(org_id) = cipher.organization_uuid.as_deref() {
        crate::api::notify::notify_org(&state, org_id, kind::SYNC_CIPHER_UPDATE, &cipher.uuid).await;
    }
    crate::api::events::log_cipher_event(
        &state,
        crate::api::events::event_type::CIPHER_SOFT_DELETED,
        &cipher.uuid,
        &headers.user.uuid,
        cipher.organization_uuid.as_deref(),
        headers.device.atype,
    )
    .await;
    (StatusCode::OK, Json(json!({})))
}

#[worker::send]
async fn restore_cipher(
    AxumState(state): AxumState<AppState>,
    headers: Headers,
    Path(uuid): Path<String>,
) -> impl IntoResponse {
    let mut cipher = match load_owned_cipher(&state, &headers, &uuid).await {
        Ok(c) => c,
        Err(e) => return e,
    };
    cipher.deleted_at = None;
    if cipher.save(&state.db).await.is_err() {
        return err_json(StatusCode::INTERNAL_SERVER_ERROR, "failed to restore cipher");
    }
    let favorite =
        Favorite::is_favorite(&state.db, &headers.user.uuid, &cipher.uuid).await.unwrap_or(false);
    notify_user(&state, &headers.user.uuid, kind::SYNC_CIPHER_UPDATE, &cipher.uuid).await;
    if let Some(org_id) = cipher.organization_uuid.as_deref() {
        crate::api::notify::notify_org(&state, org_id, kind::SYNC_CIPHER_UPDATE, &cipher.uuid).await;
    }
    crate::api::events::log_cipher_event(
        &state,
        crate::api::events::event_type::CIPHER_RESTORED,
        &cipher.uuid,
        &headers.user.uuid,
        cipher.organization_uuid.as_deref(),
        headers.device.atype,
    )
    .await;
    (StatusCode::OK, Json(cipher_to_json(&cipher, favorite)))
}

#[worker::send]
async fn delete_cipher_hard(
    AxumState(state): AxumState<AppState>,
    headers: Headers,
    Path(uuid): Path<String>,
) -> impl IntoResponse {
    let cipher = match load_owned_cipher(&state, &headers, &uuid).await {
        Ok(c) => c,
        Err(e) => return e,
    };
    let _result = Favorite::set(&state.db, &headers.user.uuid, &cipher.uuid, false).await;
    let cipher_uuid = cipher.uuid.clone();
    let cipher_org = cipher.organization_uuid.clone();
    // Best-effort R2 cleanup: drop every attachment object before the row goes.
    if let Ok(attachments) = crate::db::models::Attachment::find_by_cipher(&state.db, &cipher_uuid).await {
        for a in attachments {
            let key = format!("{cipher_uuid}/{}", a.id);
            let _r2 = state.attachments.delete(key).await;
            let _row = a.delete(&state.db).await;
        }
    }
    if cipher.delete(&state.db).await.is_err() {
        return err_json(StatusCode::INTERNAL_SERVER_ERROR, "failed to delete cipher");
    }
    notify_user(&state, &headers.user.uuid, kind::SYNC_CIPHER_DELETE, &cipher_uuid).await;
    if let Some(org_id) = cipher_org.as_deref() {
        crate::api::notify::notify_org(&state, org_id, kind::SYNC_CIPHER_DELETE, &cipher_uuid).await;
    }
    crate::api::events::log_cipher_event(
        &state,
        crate::api::events::event_type::CIPHER_DELETED,
        &cipher_uuid,
        &headers.user.uuid,
        cipher_org.as_deref(),
        headers.device.atype,
    )
    .await;
    (StatusCode::OK, Json(json!({})))
}

#[derive(Deserialize, Default)]
struct PartialUpdate {
    #[serde(default, rename = "folderId", alias = "folder_id")]
    folder_id: Option<String>,
    #[serde(default)]
    favorite: Option<bool>,
}

#[worker::send]
async fn put_cipher_partial(
    AxumState(state): AxumState<AppState>,
    headers: Headers,
    Path(uuid): Path<String>,
    Json(body): Json<PartialUpdate>,
) -> impl IntoResponse {
    let cipher = match load_owned_cipher(&state, &headers, &uuid).await {
        Ok(c) => c,
        Err(e) => return e,
    };
    set_cipher_folder(&state, &headers.user.uuid, &cipher.uuid, body.folder_id.as_deref()).await;
    if let Some(fav) = body.favorite {
        let _result = Favorite::set(&state.db, &headers.user.uuid, &cipher.uuid, fav).await;
    }
    let favorite =
        Favorite::is_favorite(&state.db, &headers.user.uuid, &cipher.uuid).await.unwrap_or(false);
    let folder = folder_for_user_cipher(&state, &headers.user.uuid, &cipher.uuid).await;
    let coll_ids = if cipher.organization_uuid.is_some() {
        CipherCollection::list_by_cipher(&state.db, &cipher.uuid).await.unwrap_or_default()
    } else {
        Vec::new()
    };
    notify_user(&state, &headers.user.uuid, kind::SYNC_CIPHER_UPDATE, &cipher.uuid).await;
    if let Some(org_id) = cipher.organization_uuid.as_deref() {
        crate::api::notify::notify_org(&state, org_id, kind::SYNC_CIPHER_UPDATE, &cipher.uuid).await;
    }
    crate::api::events::log_cipher_event(
        &state,
        crate::api::events::event_type::CIPHER_UPDATED,
        &cipher.uuid,
        &headers.user.uuid,
        cipher.organization_uuid.as_deref(),
        headers.device.atype,
    )
    .await;
    (StatusCode::OK, Json(cipher_to_json_with_folder(&cipher, favorite, &coll_ids, folder.as_deref())))
}

#[derive(Deserialize)]
struct CollectionsBody {
    #[serde(rename = "collectionIds", alias = "collection_ids", alias = "CollectionIds")]
    collection_ids: Vec<String>,
}

#[worker::send]
async fn put_cipher_collections(
    AxumState(state): AxumState<AppState>,
    headers: Headers,
    Path(uuid): Path<String>,
    Json(body): Json<CollectionsBody>,
) -> impl IntoResponse {
    let cipher = match load_owned_cipher(&state, &headers, &uuid).await {
        Ok(c) => c,
        Err(e) => return e,
    };
    let Some(org_id) = cipher.organization_uuid.as_deref() else {
        return err_json(StatusCode::BAD_REQUEST, "Cipher is not org-owned");
    };

    // Wipe existing links and re-attach exactly the requested set. Upstream
    // does the diff but the round-trip is short and idempotent.
    if let Ok(existing) = CipherCollection::list_by_cipher(&state.db, &cipher.uuid).await {
        for cid in existing {
            let _result = CipherCollection::unset(&state.db, &cipher.uuid, &cid).await;
        }
    }
    for cid in &body.collection_ids {
        let _result = CipherCollection::set(&state.db, &cipher.uuid, cid).await;
    }

    let favorite =
        Favorite::is_favorite(&state.db, &headers.user.uuid, &cipher.uuid).await.unwrap_or(false);
    let folder = folder_for_user_cipher(&state, &headers.user.uuid, &cipher.uuid).await;
    notify_user(&state, &headers.user.uuid, kind::SYNC_CIPHER_UPDATE, &cipher.uuid).await;
    crate::api::notify::notify_org(&state, org_id, kind::SYNC_CIPHER_UPDATE, &cipher.uuid).await;
    crate::api::events::log_cipher_event(
        &state,
        crate::api::events::event_type::CIPHER_UPDATED_COLLECTIONS,
        &cipher.uuid,
        &headers.user.uuid,
        Some(org_id),
        headers.device.atype,
    )
    .await;
    (
        StatusCode::OK,
        Json(cipher_to_json_with_folder(
            &cipher,
            favorite,
            &body.collection_ids,
            folder.as_deref(),
        )),
    )
}

#[derive(Deserialize)]
struct ShareCipherBody {
    #[serde(rename = "cipher")]
    cipher: CipherData,
    #[serde(rename = "collectionIds", alias = "collection_ids", alias = "CollectionIds")]
    collection_ids: Vec<String>,
}

#[worker::send]
async fn share_cipher(
    AxumState(state): AxumState<AppState>,
    headers: Headers,
    Path(uuid): Path<String>,
    Json(body): Json<ShareCipherBody>,
) -> impl IntoResponse {
    let mut cipher = match load_owned_cipher(&state, &headers, &uuid).await {
        Ok(c) => c,
        Err(e) => return e,
    };
    let Some(org_id) = body.cipher.organization_id.as_deref().filter(|s| !s.is_empty()) else {
        return err_json(StatusCode::BAD_REQUEST, "organizationId is required to share");
    };
    if body.collection_ids.is_empty() {
        return err_json(StatusCode::BAD_REQUEST, "collectionIds is required to share");
    }
    if Membership::find_by_user_and_org(&state.db, &headers.user.uuid, org_id)
        .await
        .ok()
        .flatten()
        .is_none()
    {
        return err_json(StatusCode::NOT_FOUND, "Organization not found");
    }

    cipher.organization_uuid = Some(org_id.to_owned());
    cipher.user_uuid = None;
    // The body carries the re-encrypted version of the cipher data + key for
    // the new org's key. Apply those if present.
    cipher.atype = body.cipher.atype;
    cipher.name = body.cipher.name.clone();
    cipher.notes = body.cipher.notes.clone();
    cipher.fields = body.cipher.fields.as_ref().and_then(|v| serde_json::to_string(v).ok());
    cipher.password_history =
        body.cipher.password_history.as_ref().and_then(|v| serde_json::to_string(v).ok());
    cipher.reprompt = body.cipher.reprompt;
    cipher.key = body.cipher.key.clone();
    cipher.data = data_text_for(&body.cipher);
    if cipher.save(&state.db).await.is_err() {
        return err_json(StatusCode::INTERNAL_SERVER_ERROR, "failed to save cipher");
    }

    // Wipe any prior collections, attach the new ones.
    if let Ok(existing) = CipherCollection::list_by_cipher(&state.db, &cipher.uuid).await {
        for cid in existing {
            let _result = CipherCollection::unset(&state.db, &cipher.uuid, &cid).await;
        }
    }
    for cid in &body.collection_ids {
        let _result = CipherCollection::set(&state.db, &cipher.uuid, cid).await;
    }

    let favorite =
        Favorite::is_favorite(&state.db, &headers.user.uuid, &cipher.uuid).await.unwrap_or(false);
    let folder = folder_for_user_cipher(&state, &headers.user.uuid, &cipher.uuid).await;
    notify_user(&state, &headers.user.uuid, kind::SYNC_CIPHER_UPDATE, &cipher.uuid).await;
    crate::api::notify::notify_org(&state, org_id, kind::SYNC_CIPHER_UPDATE, &cipher.uuid).await;
    crate::api::events::log_cipher_event(
        &state,
        crate::api::events::event_type::CIPHER_SHARED,
        &cipher.uuid,
        &headers.user.uuid,
        Some(org_id),
        headers.device.atype,
    )
    .await;
    (
        StatusCode::OK,
        Json(cipher_to_json_with_folder(
            &cipher,
            favorite,
            &body.collection_ids,
            folder.as_deref(),
        )),
    )
}

#[derive(Deserialize)]
struct BulkIds {
    #[serde(default, rename = "ids", alias = "Ids")]
    ids: Vec<String>,
}

#[worker::send]
async fn bulk_delete_soft(
    AxumState(state): AxumState<AppState>,
    headers: Headers,
    Json(body): Json<BulkIds>,
) -> impl IntoResponse {
    let now = now_iso();
    for id in &body.ids {
        if let Ok(mut cipher) = load_owned_cipher(&state, &headers, id).await.map_err(|_| ()) {
            cipher.deleted_at = Some(now.clone());
            let _result = cipher.save(&state.db).await;
            notify_user(&state, &headers.user.uuid, kind::SYNC_CIPHER_UPDATE, &cipher.uuid).await;
            if let Some(org_id) = cipher.organization_uuid.as_deref() {
                crate::api::notify::notify_org(&state, org_id, kind::SYNC_CIPHER_UPDATE, &cipher.uuid).await;
            }
            crate::api::events::log_cipher_event(
                &state,
                crate::api::events::event_type::CIPHER_SOFT_DELETED,
                &cipher.uuid,
                &headers.user.uuid,
                cipher.organization_uuid.as_deref(),
                headers.device.atype,
            )
            .await;
        }
    }
    (StatusCode::OK, Json(json!({})))
}

#[worker::send]
async fn bulk_restore(
    AxumState(state): AxumState<AppState>,
    headers: Headers,
    Json(body): Json<BulkIds>,
) -> impl IntoResponse {
    let mut data = Vec::new();
    for id in &body.ids {
        if let Ok(mut cipher) = load_owned_cipher(&state, &headers, id).await.map_err(|_| ()) {
            cipher.deleted_at = None;
            if cipher.save(&state.db).await.is_ok() {
                let favorite = Favorite::is_favorite(&state.db, &headers.user.uuid, &cipher.uuid)
                    .await
                    .unwrap_or(false);
                let folder = folder_for_user_cipher(&state, &headers.user.uuid, &cipher.uuid).await;
                let coll = if cipher.organization_uuid.is_some() {
                    CipherCollection::list_by_cipher(&state.db, &cipher.uuid).await.unwrap_or_default()
                } else {
                    Vec::new()
                };
                data.push(cipher_to_json_with_folder(&cipher, favorite, &coll, folder.as_deref()));
                notify_user(&state, &headers.user.uuid, kind::SYNC_CIPHER_UPDATE, &cipher.uuid).await;
                if let Some(org_id) = cipher.organization_uuid.as_deref() {
                    crate::api::notify::notify_org(&state, org_id, kind::SYNC_CIPHER_UPDATE, &cipher.uuid).await;
                }
                crate::api::events::log_cipher_event(
                    &state,
                    crate::api::events::event_type::CIPHER_RESTORED,
                    &cipher.uuid,
                    &headers.user.uuid,
                    cipher.organization_uuid.as_deref(),
                    headers.device.atype,
                )
                .await;
            }
        }
    }
    (StatusCode::OK, Json(json!({ "Object": "list", "Data": data, "ContinuationToken": Value::Null })))
}

#[derive(Deserialize)]
struct BulkMoveBody {
    #[serde(rename = "ids")]
    ids: Vec<String>,
    #[serde(default, rename = "folderId", alias = "folder_id")]
    folder_id: Option<String>,
}

#[worker::send]
async fn bulk_move(
    AxumState(state): AxumState<AppState>,
    headers: Headers,
    Json(body): Json<BulkMoveBody>,
) -> impl IntoResponse {
    for id in &body.ids {
        if (load_owned_cipher(&state, &headers, id).await).is_ok() {
            set_cipher_folder(&state, &headers.user.uuid, id, body.folder_id.as_deref()).await;
            notify_user(&state, &headers.user.uuid, kind::SYNC_CIPHER_UPDATE, id).await;
        }
    }
    (StatusCode::OK, Json(json!({})))
}

#[derive(Deserialize)]
struct BulkShareBody {
    #[serde(rename = "ids", default)]
    ids: Vec<String>,
    #[serde(default, rename = "organizationId", alias = "organization_id")]
    organization_id: Option<String>,
    #[serde(default, rename = "collectionIds", alias = "collection_ids")]
    collection_ids: Option<Vec<String>>,
}

#[worker::send]
async fn bulk_share(
    AxumState(state): AxumState<AppState>,
    headers: Headers,
    Json(body): Json<BulkShareBody>,
) -> impl IntoResponse {
    let Some(org_id) = body.organization_id.as_deref().filter(|s| !s.is_empty()) else {
        return (StatusCode::BAD_REQUEST, Json(json!({ "Message": "organizationId is required" })));
    };
    let coll_ids = body.collection_ids.unwrap_or_default();
    for id in &body.ids {
        let mut cipher = match load_owned_cipher(&state, &headers, id).await {
            Ok(c) => c,
            Err(_) => continue,
        };
        cipher.organization_uuid = Some(org_id.to_owned());
        if cipher.save(&state.db).await.is_err() {
            continue;
        }
        let existing = CipherCollection::list_by_cipher(&state.db, &cipher.uuid).await.unwrap_or_default();
        for cid in &existing {
            let _result = CipherCollection::unset(&state.db, &cipher.uuid, cid).await;
        }
        for cid in &coll_ids {
            let _result = CipherCollection::set(&state.db, &cipher.uuid, cid).await;
        }
        notify_user(&state, &headers.user.uuid, kind::SYNC_CIPHER_UPDATE, &cipher.uuid).await;
        crate::api::notify::notify_org(&state, org_id, kind::SYNC_CIPHER_UPDATE, &cipher.uuid).await;
        crate::api::events::log_cipher_event(
            &state,
            crate::api::events::event_type::CIPHER_SHARED,
            &cipher.uuid,
            &headers.user.uuid,
            Some(org_id),
            headers.device.atype,
        )
        .await;
    }
    (StatusCode::OK, Json(json!({})))
}

#[derive(Deserialize)]
struct BulkCollectionsBody {
    #[serde(rename = "cipherIds", alias = "ids", default)]
    cipher_ids: Vec<String>,
    #[serde(rename = "collectionIds", alias = "collection_ids", default)]
    collection_ids: Vec<String>,
    #[serde(default, rename = "removeCollections")]
    remove_collections: Option<bool>,
}

#[worker::send]
async fn bulk_collections(
    AxumState(state): AxumState<AppState>,
    headers: Headers,
    Json(body): Json<BulkCollectionsBody>,
) -> impl IntoResponse {
    let remove = body.remove_collections.unwrap_or(false);
    for id in &body.cipher_ids {
        let cipher = match load_owned_cipher(&state, &headers, id).await {
            Ok(c) => c,
            Err(_) => continue,
        };
        for cid in &body.collection_ids {
            if remove {
                let _result = CipherCollection::unset(&state.db, &cipher.uuid, cid).await;
            } else {
                let _result = CipherCollection::set(&state.db, &cipher.uuid, cid).await;
            }
        }
        notify_user(&state, &headers.user.uuid, kind::SYNC_CIPHER_UPDATE, &cipher.uuid).await;
        if let Some(org_id) = cipher.organization_uuid.as_deref() {
            crate::api::notify::notify_org(&state, org_id, kind::SYNC_CIPHER_UPDATE, &cipher.uuid).await;
        }
        crate::api::events::log_cipher_event(
            &state,
            crate::api::events::event_type::CIPHER_UPDATED_COLLECTIONS,
            &cipher.uuid,
            &headers.user.uuid,
            cipher.organization_uuid.as_deref(),
            headers.device.atype,
        )
        .await;
    }
    (StatusCode::OK, Json(json!({})))
}

#[worker::send]
async fn list_org_ciphers(
    AxumState(state): AxumState<AppState>,
    headers: Headers,
) -> impl IntoResponse {
    let ciphers = Cipher::find_visible_to_user(&state.db, &headers.user.uuid).await.unwrap_or_default();
    let mut data = Vec::new();
    for c in ciphers.into_iter().filter(|c| c.organization_uuid.is_some()) {
        let favorite = Favorite::is_favorite(&state.db, &headers.user.uuid, &c.uuid).await.unwrap_or(false);
        let coll = CipherCollection::list_by_cipher(&state.db, &c.uuid).await.unwrap_or_default();
        let folder = folder_for_user_cipher(&state, &headers.user.uuid, &c.uuid).await;
        data.push(cipher_to_json_with_folder(&c, favorite, &coll, folder.as_deref()));
    }
    (
        StatusCode::OK,
        Json(json!({ "Object": "list", "Data": data, "ContinuationToken": Value::Null })),
    )
}

#[derive(Deserialize)]
struct PurgeBody {
    #[serde(default, rename = "masterPasswordHash")]
    master_password_hash: Option<String>,
}

#[derive(Deserialize, Default)]
struct PurgeQuery {
    #[serde(default, alias = "organizationId")]
    organization_id: Option<String>,
}

#[worker::send]
async fn purge_user_ciphers(
    AxumState(state): AxumState<AppState>,
    headers: Headers,
    axum::extract::Query(q): axum::extract::Query<PurgeQuery>,
    Json(body): Json<PurgeBody>,
) -> impl IntoResponse {
    let pw = match body.master_password_hash.as_deref() {
        Some(p) => p,
        None => return err_json(StatusCode::BAD_REQUEST, "masterPasswordHash is required"),
    };
    if !headers.user.check_valid_password(pw) {
        return err_json(StatusCode::UNAUTHORIZED, "Invalid password");
    }

    // Org-scoped purge: only the org Owner may run it. Mirrors upstream's
    // /ciphers/purge?organization=... shape.
    if let Some(org_id) = q.organization_id.as_deref() {
        use crate::db::models::Membership;
        let m = match Membership::find_by_user_and_org(&state.db, &headers.user.uuid, org_id).await {
            Ok(Some(m)) if m.atype == 0 => m,
            _ => return err_json(StatusCode::FORBIDDEN, "Owner access required"),
        };
        drop(m);
        let ciphers = Cipher::find_by_org(&state.db, org_id).await.unwrap_or_default();
        for c in ciphers {
            if let Ok(attachments) = crate::db::models::Attachment::find_by_cipher(&state.db, &c.uuid).await {
                for a in attachments {
                    let key = format!("{}/{}", c.uuid, a.id);
                    let _r2 = state.attachments.delete(key).await;
                    let _row = a.delete(&state.db).await;
                }
            }
            let _delete = c.delete(&state.db).await;
        }
        crate::api::events::log_org_event(
            &state,
            crate::api::events::event_type::ORG_PURGED_VAULT,
            org_id,
            &headers.user.uuid,
            None,
            headers.device.atype,
        )
        .await;
        notify_user(&state, &headers.user.uuid, kind::SYNC_VAULT, "").await;
        crate::api::notify::notify_org(&state, org_id, kind::SYNC_VAULT, org_id).await;
        return (StatusCode::OK, Json(json!({})));
    }

    let ciphers = Cipher::find_owned_by_user(&state.db, &headers.user.uuid).await.unwrap_or_default();
    for c in ciphers {
        // Best-effort: delete every attachment from R2 first so the user
        // doesn't pay storage for orphaned files, then drop the rows.
        if let Ok(attachments) = crate::db::models::Attachment::find_by_cipher(&state.db, &c.uuid).await {
            for a in attachments {
                let key = format!("{}/{}", c.uuid, a.id);
                let _r2 = state.attachments.delete(key).await;
                let _row = a.delete(&state.db).await;
            }
        }
        let _result = Favorite::set(&state.db, &headers.user.uuid, &c.uuid, false).await;
        let _delete = c.delete(&state.db).await;
    }
    notify_user(&state, &headers.user.uuid, kind::SYNC_VAULT, "").await;
    (StatusCode::OK, Json(json!({})))
}

#[derive(Deserialize)]
struct ImportBody {
    #[serde(default)]
    folders: Vec<ImportFolder>,
    #[serde(default)]
    ciphers: Vec<CipherData>,
    #[serde(default, alias = "FolderRelationships", alias = "folderRelationships")]
    folder_relationships: Vec<FolderRelation>,
    /// Set when importing into an organization. Sourced from the
    /// `organizationId` query string on `/api/ciphers/import-organization`,
    /// or from the body field on legacy clients. When present, ciphers are
    /// org-owned (user_uuid = NULL) and linked to the specified collections.
    #[serde(default, rename = "organizationId", alias = "organization_id")]
    organization_id: Option<String>,
    #[serde(default, alias = "Collections", alias = "collections")]
    collections: Vec<ImportCollection>,
    #[serde(
        default,
        rename = "collectionRelationships",
        alias = "CollectionRelationships",
        alias = "collection_relationships"
    )]
    collection_relationships: Vec<FolderRelation>,
}

#[derive(Deserialize)]
struct ImportCollection {
    name: String,
    #[serde(default, alias = "externalId")]
    external_id: Option<String>,
}

#[derive(Deserialize)]
struct ImportFolder {
    name: String,
}

#[derive(Deserialize)]
struct FolderRelation {
    key: usize,   // cipher index
    value: usize, // folder index
}

#[worker::send]
async fn import_ciphers(
    AxumState(state): AxumState<AppState>,
    headers: Headers,
    Json(body): Json<ImportBody>,
) -> impl IntoResponse {
    // If targeting an organization, ensure the caller is an admin/manager+ of
    // that org. Personal imports skip this check.
    if let Some(org_id) = body.organization_id.as_deref().filter(|s| !s.is_empty()) {
        let m = match Membership::find_by_user_and_org(&state.db, &headers.user.uuid, org_id).await {
            Ok(Some(m)) => m,
            _ => return err_json(StatusCode::FORBIDDEN, "Not a member of that organization"),
        };
        // Owner=0, Admin=1, Manager=3 (per upstream MembershipType). Users
        // import only to personal vault.
        if m.atype > 3 {
            return err_json(StatusCode::FORBIDDEN, "Insufficient permissions to import to organization");
        }
    }

    let target_org = body.organization_id.as_deref().filter(|s| !s.is_empty()).map(str::to_owned);

    // 1. Create folders or org collections in input order, capturing UUIDs.
    let mut folder_ids: Vec<String> = Vec::with_capacity(body.folders.len());
    if target_org.is_none() {
        for f in &body.folders {
            let mut folder = crate::db::models::Folder::new(headers.user.uuid.clone(), f.name.clone());
            if folder.save(&state.db).await.is_err() {
                return err_json(StatusCode::INTERNAL_SERVER_ERROR, "failed to save folder");
            }
            folder_ids.push(folder.uuid);
        }
    }

    let mut collection_ids: Vec<String> = Vec::with_capacity(body.collections.len());
    if let Some(org_id) = target_org.as_deref() {
        for col in &body.collections {
            let mut c = crate::db::models::Collection::new(org_id.to_owned(), col.name.clone());
            c.external_id = col.external_id.clone();
            if c.save(&state.db).await.is_err() {
                return err_json(StatusCode::INTERNAL_SERVER_ERROR, "failed to save collection");
            }
            collection_ids.push(c.uuid);
        }
    }

    // 2. Create ciphers, scoping by user or org based on target_org.
    let mut cipher_ids: Vec<String> = Vec::with_capacity(body.ciphers.len());
    for c in &body.ciphers {
        let mut cipher = Cipher::new(c.atype, c.name.clone());
        if let Some(ref org_id) = target_org {
            cipher.user_uuid = None;
            cipher.organization_uuid = Some(org_id.clone());
        } else {
            cipher.user_uuid = Some(headers.user.uuid.clone());
        }
        cipher.notes = c.notes.clone();
        cipher.fields = c.fields.as_ref().and_then(|v| serde_json::to_string(v).ok());
        cipher.password_history = c.password_history.as_ref().and_then(|v| serde_json::to_string(v).ok());
        cipher.reprompt = c.reprompt;
        cipher.key = c.key.clone();
        cipher.data = data_text_for(c);
        if cipher.save(&state.db).await.is_err() {
            return err_json(StatusCode::INTERNAL_SERVER_ERROR, "failed to save cipher");
        }
        if c.favorite.unwrap_or(false) {
            let _result = Favorite::set(&state.db, &headers.user.uuid, &cipher.uuid, true).await;
        }
        crate::api::events::log_cipher_event(
            &state,
            crate::api::events::event_type::CIPHER_CREATED,
            &cipher.uuid,
            &headers.user.uuid,
            cipher.organization_uuid.as_deref(),
            headers.device.atype,
        )
        .await;
        cipher_ids.push(cipher.uuid);
    }

    // 3. Apply folder relationships (cipher index → folder index) for personal
    //    imports, or collection relationships for org imports.
    if target_org.is_some() {
        for rel in &body.collection_relationships {
            if let (Some(cid), Some(coll_id)) =
                (cipher_ids.get(rel.key), collection_ids.get(rel.value))
            {
                let _result = CipherCollection::set(&state.db, cid, coll_id).await;
            }
        }
    } else {
        for rel in &body.folder_relationships {
            if let (Some(cid), Some(fid)) = (cipher_ids.get(rel.key), folder_ids.get(rel.value)) {
                let _result = FolderCipher::set(&state.db, cid, fid).await;
            }
        }
    }

    notify_user(&state, &headers.user.uuid, kind::SYNC_VAULT, "").await;
    if let Some(org_id) = target_org.as_deref() {
        crate::api::notify::notify_org(&state, org_id, kind::SYNC_VAULT, org_id).await;
    }
    state.telemetry.record(
        "import",
        &[
            ("user", &headers.user.uuid),
            ("folders", &folder_ids.len().to_string()),
            ("ciphers", &cipher_ids.len().to_string()),
        ],
    );
    (StatusCode::OK, Json(json!({})))
}

#[worker::send]
async fn archive_cipher(
    AxumState(state): AxumState<AppState>,
    headers: Headers,
    Path(uuid): Path<String>,
) -> impl IntoResponse {
    let cipher = match load_owned_cipher(&state, &headers, &uuid).await {
        Ok(c) => c,
        Err(e) => return e,
    };
    let _set = Archive::set(&state.db, &headers.user.uuid, &cipher.uuid).await;
    let favorite = Favorite::is_favorite(&state.db, &headers.user.uuid, &cipher.uuid).await.unwrap_or(false);
    let folder = folder_for_user_cipher(&state, &headers.user.uuid, &cipher.uuid).await;
    let coll = if cipher.organization_uuid.is_some() {
        CipherCollection::list_by_cipher(&state.db, &cipher.uuid).await.unwrap_or_default()
    } else {
        Vec::new()
    };
    notify_user(&state, &headers.user.uuid, kind::SYNC_CIPHER_UPDATE, &cipher.uuid).await;
    (StatusCode::OK, Json(cipher_to_json_with_folder(&cipher, favorite, &coll, folder.as_deref())))
}

#[worker::send]
async fn unarchive_cipher(
    AxumState(state): AxumState<AppState>,
    headers: Headers,
    Path(uuid): Path<String>,
) -> impl IntoResponse {
    let cipher = match load_owned_cipher(&state, &headers, &uuid).await {
        Ok(c) => c,
        Err(e) => return e,
    };
    let _unset = Archive::unset(&state.db, &headers.user.uuid, &cipher.uuid).await;
    let favorite = Favorite::is_favorite(&state.db, &headers.user.uuid, &cipher.uuid).await.unwrap_or(false);
    let folder = folder_for_user_cipher(&state, &headers.user.uuid, &cipher.uuid).await;
    let coll = if cipher.organization_uuid.is_some() {
        CipherCollection::list_by_cipher(&state.db, &cipher.uuid).await.unwrap_or_default()
    } else {
        Vec::new()
    };
    notify_user(&state, &headers.user.uuid, kind::SYNC_CIPHER_UPDATE, &cipher.uuid).await;
    (StatusCode::OK, Json(cipher_to_json_with_folder(&cipher, favorite, &coll, folder.as_deref())))
}

#[worker::send]
async fn bulk_archive(
    AxumState(state): AxumState<AppState>,
    headers: Headers,
    Json(body): Json<BulkIds>,
) -> impl IntoResponse {
    for id in &body.ids {
        if (load_owned_cipher(&state, &headers, id).await).is_ok() {
            let _set = Archive::set(&state.db, &headers.user.uuid, id).await;
            notify_user(&state, &headers.user.uuid, kind::SYNC_CIPHER_UPDATE, id).await;
        }
    }
    (StatusCode::OK, Json(json!({})))
}

#[worker::send]
async fn bulk_unarchive(
    AxumState(state): AxumState<AppState>,
    headers: Headers,
    Json(body): Json<BulkIds>,
) -> impl IntoResponse {
    for id in &body.ids {
        if (load_owned_cipher(&state, &headers, id).await).is_ok() {
            let _unset = Archive::unset(&state.db, &headers.user.uuid, id).await;
            notify_user(&state, &headers.user.uuid, kind::SYNC_CIPHER_UPDATE, id).await;
        }
    }
    (StatusCode::OK, Json(json!({})))
}
