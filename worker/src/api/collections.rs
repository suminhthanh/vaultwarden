use axum::{
    Json, Router,
    extract::{Path, State as AxumState},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::AppState;
use crate::auth::Headers;
use crate::db::models::{Collection, Membership, UserCollection};

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/collections", get(list_all_collections))
        .route(
            "/api/organizations/{org_id}/collections",
            get(list_org_collections).post(post_collection),
        )
        .route(
            "/api/organizations/{org_id}/collections/details",
            get(list_org_collections),
        )
        .route(
            "/api/organizations/{org_id}/collections/{col_id}",
            get(get_collection).put(put_collection).post(put_collection).delete(delete_collection),
        )
        .route(
            "/api/organizations/{org_id}/collections/{col_id}/details",
            get(get_collection),
        )
        .route(
            "/api/organizations/{org_id}/collections/{col_id}/users",
            get(list_collection_users).put(set_collection_users),
        )
        .route("/api/organizations/{org_id}/collections/{col_id}/delete", post(delete_collection))
        .route("/api/organizations/{org_id}/collections/bulk-access", post(bulk_collection_access))
}

fn err_json(code: StatusCode, msg: &str) -> (StatusCode, Json<Value>) {
    (code, Json(json!({ "ErrorModel": { "Message": msg }, "Object": "error", "Message": msg })))
}

pub(crate) fn collection_to_json(c: &Collection) -> Value {
    json!({
        "Object": "collectionDetails",
        "Id": c.uuid,
        "OrganizationId": c.org_uuid,
        "Name": c.name,
        "ExternalId": c.external_id,
        "ReadOnly": false,
        "HidePasswords": false,
        "Manage": true,
    })
}

/// Like `collection_to_json` but flags ReadOnly/HidePasswords/Manage based on
/// the caller's role + per-user-collection ACLs. Owners and Admins always
/// manage; otherwise consult the users_collections row.
pub(crate) fn collection_to_json_for(
    c: &Collection,
    membership_atype: i32,
    acl: Option<&UserCollection>,
) -> Value {
    // 0=Owner, 1=Admin, 3=Manager — match the constants used in
    // `organizations.rs::can_manage`. Anyone Manager+ effectively manages
    // every collection in the org, so they get full permissions.
    let manages_org = matches!(membership_atype, 0 | 1 | 3);
    let (read_only, hide_passwords, manage) = if manages_org {
        (false, false, true)
    } else if let Some(a) = acl {
        (a.read_only == 1, a.hide_passwords == 1, a.manage == 1)
    } else {
        // Not explicitly assigned: visible (so the client doesn't break) but
        // read-only.
        (true, false, false)
    };
    json!({
        "Object": "collectionDetails",
        "Id": c.uuid,
        "OrganizationId": c.org_uuid,
        "Name": c.name,
        "ExternalId": c.external_id,
        "ReadOnly": read_only,
        "HidePasswords": hide_passwords,
        "Manage": manage,
    })
}

#[derive(Deserialize)]
struct CollectionData {
    name: String,
    #[serde(default, alias = "externalId")]
    external_id: Option<String>,
    /// Full PUT shape: re-key the collection's user ACLs in the same call.
    /// `id` here is a Membership uuid (translated to user_uuid below).
    #[serde(default)]
    users: Option<Vec<CollectionUserEntry>>,
    /// Full PUT shape: re-key the collection's group ACLs in the same call.
    #[serde(default)]
    groups: Option<Vec<CollectionGroupEntry>>,
}

async fn require_membership(
    state: &AppState,
    headers: &Headers,
    org_id: &str,
) -> Result<Membership, (StatusCode, Json<Value>)> {
    Membership::find_by_user_and_org(&state.db, &headers.user.uuid, org_id)
        .await
        .map_err(|_| err_json(StatusCode::INTERNAL_SERVER_ERROR, "database error"))?
        .ok_or_else(|| err_json(StatusCode::NOT_FOUND, "Organization not found"))
}

#[worker::send]
async fn list_all_collections(
    AxumState(state): AxumState<AppState>,
    headers: Headers,
) -> impl IntoResponse {
    let memberships = match Membership::find_by_user(&state.db, &headers.user.uuid).await {
        Ok(m) => m,
        Err(_) => return err_json(StatusCode::INTERNAL_SERVER_ERROR, "database error"),
    };
    let acls = UserCollection::find_by_user(&state.db, &headers.user.uuid).await.unwrap_or_default();
    let mut data = Vec::new();
    for m in memberships {
        if let Ok(cs) = Collection::find_by_org(&state.db, &m.org_uuid).await {
            for c in cs.iter() {
                let acl = acls.iter().find(|a| a.collection_uuid == c.uuid);
                data.push(collection_to_json_for(c, m.atype, acl));
            }
        }
    }
    (StatusCode::OK, Json(json!({ "Object": "list", "Data": data, "ContinuationToken": Value::Null })))
}

#[worker::send]
async fn list_org_collections(
    AxumState(state): AxumState<AppState>,
    headers: Headers,
    Path(org_id): Path<String>,
) -> impl IntoResponse {
    let m = match require_membership(&state, &headers, &org_id).await {
        Ok(m) => m,
        Err(e) => return e,
    };
    let cs = match Collection::find_by_org(&state.db, &org_id).await {
        Ok(c) => c,
        Err(_) => return err_json(StatusCode::INTERNAL_SERVER_ERROR, "database error"),
    };
    let acls = UserCollection::find_by_user(&state.db, &headers.user.uuid).await.unwrap_or_default();
    let data: Vec<Value> = cs
        .iter()
        .map(|c| collection_to_json_for(c, m.atype, acls.iter().find(|a| a.collection_uuid == c.uuid)))
        .collect();
    (StatusCode::OK, Json(json!({ "Object": "list", "Data": data, "ContinuationToken": Value::Null })))
}

#[worker::send]
async fn post_collection(
    AxumState(state): AxumState<AppState>,
    headers: Headers,
    Path(org_id): Path<String>,
    Json(body): Json<CollectionData>,
) -> impl IntoResponse {
    use crate::db::models::CollectionGroup;

    if let Err(e) = require_membership(&state, &headers, &org_id).await {
        return e;
    }
    let mut col = Collection::new(org_id.clone(), body.name);
    col.external_id = body.external_id;
    if col.save(&state.db).await.is_err() {
        return err_json(StatusCode::INTERNAL_SERVER_ERROR, "failed to save collection");
    }
    // FullCollectionData shape: persist user + group ACLs in the same call
    // so the org admin can hand-pick the visibility set at creation time
    // without a follow-up PUT.
    if let Some(users) = body.users {
        for entry in users {
            let user_uuid = match Membership::find_by_uuid(&state.db, &entry.id).await {
                Ok(Some(m)) if m.org_uuid == org_id && m.access_all == 0 => m.user_uuid,
                _ => continue,
            };
            let acl = UserCollection::new(
                user_uuid,
                col.uuid.clone(),
                entry.read_only,
                entry.hide_passwords,
                entry.manage,
            );
            let _save = acl.upsert(&state.db).await;
        }
    }
    if let Some(groups) = body.groups {
        for entry in groups {
            let cg = CollectionGroup::new(
                col.uuid.clone(),
                entry.id.clone(),
                entry.read_only,
                entry.hide_passwords,
                entry.manage,
            );
            let _set = cg.set(&state.db).await;
        }
    }
    crate::api::events::log_org_event(
        &state,
        crate::api::events::event_type::COLLECTION_CREATED,
        &org_id,
        &headers.user.uuid,
        None,
        headers.device.atype,
    )
    .await;
    crate::api::notify::notify_org(
        &state,
        &org_id,
        crate::api::notify::kind::SYNC_VAULT,
        &org_id,
    )
    .await;
    (StatusCode::OK, Json(collection_to_json(&col)))
}

async fn load_org_collection(
    state: &AppState,
    headers: &Headers,
    org_id: &str,
    col_id: &str,
) -> Result<Collection, (StatusCode, Json<Value>)> {
    require_membership(state, headers, org_id).await?;
    let c = Collection::find_by_uuid(&state.db, col_id)
        .await
        .map_err(|_| err_json(StatusCode::INTERNAL_SERVER_ERROR, "database error"))?
        .ok_or_else(|| err_json(StatusCode::NOT_FOUND, "Collection not found"))?;
    if c.org_uuid != org_id {
        return Err(err_json(StatusCode::NOT_FOUND, "Collection not found"));
    }
    Ok(c)
}

#[worker::send]
async fn get_collection(
    AxumState(state): AxumState<AppState>,
    headers: Headers,
    Path((org_id, col_id)): Path<(String, String)>,
) -> impl IntoResponse {
    let c = match load_org_collection(&state, &headers, &org_id, &col_id).await {
        Ok(c) => c,
        Err(e) => return e,
    };
    (StatusCode::OK, Json(collection_to_json(&c)))
}

#[worker::send]
async fn put_collection(
    AxumState(state): AxumState<AppState>,
    headers: Headers,
    Path((org_id, col_id)): Path<(String, String)>,
    Json(body): Json<CollectionData>,
) -> impl IntoResponse {
    use crate::db::models::CollectionGroup;

    let mut c = match load_org_collection(&state, &headers, &org_id, &col_id).await {
        Ok(c) => c,
        Err(e) => return e,
    };
    c.name = body.name;
    c.external_id = body.external_id;
    if c.save(&state.db).await.is_err() {
        return err_json(StatusCode::INTERNAL_SERVER_ERROR, "failed to save collection");
    }
    // Optional FullCollectionData shape: re-key user + group ACLs in the same
    // PUT. Mirrors upstream's put_organization_collection_update.
    if let Some(users) = body.users {
        let _drop = UserCollection::delete_all_by_collection(&state.db, &col_id).await;
        for entry in users {
            let user_uuid = match Membership::find_by_uuid(&state.db, &entry.id).await {
                Ok(Some(m)) if m.org_uuid == org_id && m.access_all == 0 => m.user_uuid,
                _ => continue,
            };
            let acl = UserCollection::new(
                user_uuid,
                col_id.clone(),
                entry.read_only,
                entry.hide_passwords,
                entry.manage,
            );
            let _save = acl.upsert(&state.db).await;
        }
    }
    if let Some(groups) = body.groups {
        let _drop = CollectionGroup::delete_all_by_collection(&state.db, &col_id).await;
        for entry in groups {
            let cg = CollectionGroup::new(
                col_id.clone(),
                entry.id.clone(),
                entry.read_only,
                entry.hide_passwords,
                entry.manage,
            );
            let _set = cg.set(&state.db).await;
        }
    }
    crate::api::events::log_org_event(
        &state,
        crate::api::events::event_type::COLLECTION_UPDATED,
        &org_id,
        &headers.user.uuid,
        None,
        headers.device.atype,
    )
    .await;
    crate::api::notify::notify_org(
        &state,
        &org_id,
        crate::api::notify::kind::SYNC_VAULT,
        &org_id,
    )
    .await;
    (StatusCode::OK, Json(collection_to_json(&c)))
}

#[worker::send]
async fn delete_collection(
    AxumState(state): AxumState<AppState>,
    headers: Headers,
    Path((org_id, col_id)): Path<(String, String)>,
) -> impl IntoResponse {
    let c = match load_org_collection(&state, &headers, &org_id, &col_id).await {
        Ok(c) => c,
        Err(e) => return e,
    };
    // Drop ACL + cipher links + group assignments before the collection row
    // disappears. Each of these tables references collection_uuid by FK in
    // upstream's MySQL/Postgres schema; D1 doesn't enforce them so we clean
    // up by hand.
    let bind = worker::wasm_bindgen::JsValue::from_str(&col_id);
    for sql in [
        "DELETE FROM ciphers_collections WHERE collection_uuid = ?1",
        "DELETE FROM users_collections WHERE collection_uuid = ?1",
        "DELETE FROM collections_groups WHERE collections_uuid = ?1",
    ] {
        if let Ok(stmt) = state.db.prepare(sql).bind(&[bind.clone()]) {
            let _r = stmt.run().await;
        }
    }
    if c.delete(&state.db).await.is_err() {
        return err_json(StatusCode::INTERNAL_SERVER_ERROR, "failed to delete collection");
    }
    crate::api::events::log_org_event(
        &state,
        crate::api::events::event_type::COLLECTION_DELETED,
        &org_id,
        &headers.user.uuid,
        None,
        headers.device.atype,
    )
    .await;
    crate::api::notify::notify_org(
        &state,
        &org_id,
        crate::api::notify::kind::SYNC_VAULT,
        &org_id,
    )
    .await;
    (StatusCode::OK, Json(json!({})))
}

#[worker::send]
async fn list_collection_users(
    AxumState(state): AxumState<AppState>,
    headers: Headers,
    Path((org_id, col_id)): Path<(String, String)>,
) -> impl IntoResponse {
    use crate::db::models::{CollectionGroup, Membership};

    if let Err(e) = load_org_collection(&state, &headers, &org_id, &col_id).await {
        return e;
    }
    let acls = UserCollection::find_by_collection(&state.db, &col_id).await.unwrap_or_default();
    let mut data: Vec<Value> = Vec::with_capacity(acls.len());
    // Resolve user_uuid → membership uuid so the client gets the same id it
    // posted in set_collection_users.
    for a in &acls {
        let membership_id = match Membership::find_by_user_and_org(&state.db, &a.user_uuid, &org_id).await {
            Ok(Some(m)) => m.uuid,
            _ => a.user_uuid.clone(),
        };
        data.push(json!({
            "Object": "selectionReadOnly",
            "Id": membership_id,
            "ReadOnly": a.read_only == 1,
            "HidePasswords": a.hide_passwords == 1,
            "Manage": a.manage == 1,
        }));
    }
    let groups = CollectionGroup::find_by_collection(&state.db, &col_id).await.unwrap_or_default();
    for g in groups {
        data.push(json!({
            "Object": "selectionReadOnly",
            "Id": g.groups_uuid,
            "ReadOnly": g.read_only == 1,
            "HidePasswords": g.hide_passwords == 1,
            "Manage": g.manage == 1,
        }));
    }
    (StatusCode::OK, Json(json!(data)))
}

#[derive(Deserialize)]
struct CollectionGroupEntry {
    id: String,
    #[serde(default, rename = "readOnly")]
    read_only: bool,
    #[serde(default, rename = "hidePasswords")]
    hide_passwords: bool,
    #[serde(default)]
    manage: bool,
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct CollectionUsersBody {
    #[serde(default)]
    users: Vec<CollectionUserEntry>,
    #[serde(default)]
    groups: Vec<CollectionGroupEntry>,
}

#[derive(Deserialize)]
struct CollectionUserEntry {
    id: String,
    #[serde(default, rename = "readOnly")]
    read_only: bool,
    #[serde(default, rename = "hidePasswords")]
    hide_passwords: bool,
    #[serde(default)]
    manage: bool,
}

#[worker::send]
async fn set_collection_users(
    AxumState(state): AxumState<AppState>,
    headers: Headers,
    Path((org_id, col_id)): Path<(String, String)>,
    Json(body): Json<CollectionUsersBody>,
) -> impl IntoResponse {
    use crate::db::models::CollectionGroup;

    if let Err(e) = load_org_collection(&state, &headers, &org_id, &col_id).await {
        return e;
    }
    // Reset existing user + group ACLs, then replace with the supplied set.
    // body.users[*].id is a membership UUID — translate to user UUID via Membership.
    let existing = UserCollection::find_by_collection(&state.db, &col_id).await.unwrap_or_default();
    for entry in existing {
        let _del = entry.delete(&state.db).await;
    }
    for entry in body.users {
        let user_uuid = match Membership::find_by_uuid(&state.db, &entry.id).await {
            Ok(Some(m)) if m.org_uuid == org_id => m.user_uuid,
            _ => continue,
        };
        let acl = UserCollection::new(
            user_uuid,
            col_id.clone(),
            entry.read_only,
            entry.hide_passwords,
            entry.manage,
        );
        let _save = acl.upsert(&state.db).await;
    }
    let _drop = CollectionGroup::delete_all_by_collection(&state.db, &col_id).await;
    for entry in body.groups {
        let cg = CollectionGroup::new(
            col_id.clone(),
            entry.id.clone(),
            entry.read_only,
            entry.hide_passwords,
            entry.manage,
        );
        let _set = cg.set(&state.db).await;
    }
    crate::api::events::log_org_event(
        &state,
        crate::api::events::event_type::COLLECTION_UPDATED,
        &org_id,
        &headers.user.uuid,
        None,
        headers.device.atype,
    )
    .await;
    (StatusCode::OK, Json(json!([])))
}

#[derive(Deserialize)]
struct BulkAccessGroup {
    id: String,
    #[serde(default, alias = "readOnly")]
    read_only: bool,
    #[serde(default, alias = "hidePasswords")]
    hide_passwords: bool,
    #[serde(default)]
    manage: bool,
}

#[derive(Deserialize)]
struct BulkAccessUser {
    id: String,
    #[serde(default, alias = "readOnly")]
    read_only: bool,
    #[serde(default, alias = "hidePasswords")]
    hide_passwords: bool,
    #[serde(default)]
    manage: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct BulkCollectionAccessBody {
    collection_ids: Vec<String>,
    #[serde(default)]
    groups: Vec<BulkAccessGroup>,
    #[serde(default)]
    users: Vec<BulkAccessUser>,
}

/// Replace the user/group ACLs on each named collection with a fresh set.
/// Mirrors upstream `post_bulk_access_collections`. Manager-only — checked
/// via `require_manage_org`.
#[worker::send]
async fn bulk_collection_access(
    AxumState(state): AxumState<AppState>,
    headers: Headers,
    Path(org_id): Path<String>,
    Json(body): Json<BulkCollectionAccessBody>,
) -> impl IntoResponse {
    use crate::db::models::{CollectionGroup, Membership};

    let m = match require_membership(&state, &headers, &org_id).await {
        Ok(m) => m,
        Err(e) => return e,
    };
    // Owners=0, Admins=1, Managers=3 may modify ACLs.
    if !matches!(m.atype, 0 | 1 | 3) {
        return err_json(StatusCode::FORBIDDEN, "Manager access required");
    }
    for col_id in &body.collection_ids {
        let collection = match Collection::find_by_uuid(&state.db, col_id).await {
            Ok(Some(c)) if c.org_uuid == org_id => c,
            _ => return err_json(StatusCode::NOT_FOUND, "Collection not found"),
        };
        // Touch the row so updated_at advances + clients re-sync.
        if collection.save(&state.db).await.is_err() {
            return err_json(StatusCode::INTERNAL_SERVER_ERROR, "save failed");
        }
        // Replace group ACLs.
        let _drop = CollectionGroup::delete_all_by_collection(&state.db, col_id).await;
        for g in &body.groups {
            let cg = CollectionGroup::new(
                col_id.clone(),
                g.id.clone(),
                g.read_only,
                g.hide_passwords,
                g.manage,
            );
            let _set = cg.set(&state.db).await;
        }
        // Replace user ACLs.
        let _drop = UserCollection::delete_all_by_collection(&state.db, col_id).await;
        for u in &body.users {
            // u.id is a Membership uuid; resolve to user uuid first.
            let member = match Membership::find_by_uuid(&state.db, &u.id).await {
                Ok(Some(mem)) if mem.org_uuid == org_id => mem,
                _ => continue,
            };
            if member.access_all == 1 {
                continue;
            }
            let uc = UserCollection::new(
                member.user_uuid,
                col_id.clone(),
                u.read_only,
                u.hide_passwords,
                u.manage,
            );
            let _up = uc.upsert(&state.db).await;
        }
        crate::api::events::log_org_event(
            &state,
            crate::api::events::event_type::COLLECTION_UPDATED,
            &org_id,
            &headers.user.uuid,
            None,
            headers.device.atype,
        )
        .await;
    }
    (StatusCode::OK, Json(json!({})))
}
