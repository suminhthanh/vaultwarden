//! Org policies + groups.
//!
//! Policies: simple JSON-payload key/value gating on (org, type). Groups:
//! membership grouping inside an org with optional access_all and per-collection
//! ACL hints. Mirrors upstream's `/organizations/{org}/policies/*` and
//! `/organizations/{org}/groups/*` shapes.

use axum::{
    Json, Router,
    extract::{Path, State as AxumState},
    http::StatusCode,
    response::IntoResponse,
    routing::{delete, get, post, put},
};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::AppState;
use crate::auth::Headers;
use crate::db::models::{Group, GroupUser, Membership, OrgPolicy};

pub fn routes() -> Router<AppState> {
    Router::new()
        // Policies
        .route("/api/organizations/{org_id}/policies", get(list_policies))
        .route(
            "/api/organizations/{org_id}/policies/{atype}",
            get(get_policy).put(put_policy),
        )
        .route(
            "/api/organizations/{org_id}/policies/{atype}/vnext",
            put(put_policy),
        )
        .route(
            "/api/organizations/{org_id}/policies/master-password",
            get(master_password_policy),
        )
        .route("/api/organizations/{org_id}/policies/token", get(policies_by_token))
        // Groups
        .route("/api/organizations/{org_id}/groups", get(list_groups).post(post_group))
        .route("/api/organizations/{org_id}/groups/details", get(list_groups_details))
        .route(
            "/api/organizations/{org_id}/groups/{group_id}",
            get(get_group).put(put_group).post(put_group).delete(delete_group),
        )
        .route(
            "/api/organizations/{org_id}/groups/{group_id}/details",
            get(get_group_details),
        )
        .route(
            "/api/organizations/{org_id}/groups/{group_id}/users",
            get(group_users).put(set_group_users),
        )
        .route(
            "/api/organizations/{org_id}/groups/{group_id}/delete-user/{member_id}",
            post(remove_group_user).delete(remove_group_user),
        )
        .route(
            "/api/organizations/{org_id}/groups/{group_id}/delete",
            post(delete_group).delete(delete_group),
        )
        .route("/api/organizations/{org_id}/groups", delete(bulk_delete_groups))
}

fn err(code: StatusCode, msg: &str) -> (StatusCode, Json<Value>) {
    (code, Json(json!({ "ErrorModel": { "Message": msg }, "Object": "error", "Message": msg })))
}

fn policy_json(p: &OrgPolicy) -> Value {
    let data: Value = serde_json::from_str(&p.data).unwrap_or(Value::Null);
    json!({
        "Object": "policy",
        "Id": p.uuid,
        "OrganizationId": p.org_uuid,
        "Type": p.atype,
        "Enabled": p.enabled == 1,
        "Data": data,
    })
}

fn group_json(g: &Group) -> Value {
    json!({
        "Object": "group",
        "Id": g.uuid,
        "OrganizationId": g.organizations_uuid,
        "Name": g.name,
        "AccessAll": g.access_all == 1,
        "ExternalId": g.external_id,
        "RevisionDate": g.revision_date,
        "CreationDate": g.creation_date,
    })
}

async fn require_member(
    state: &AppState,
    headers: &Headers,
    org_id: &str,
) -> Result<Membership, (StatusCode, Json<Value>)> {
    Membership::find_by_user_and_org(&state.db, &headers.user.uuid, org_id)
        .await
        .ok()
        .flatten()
        .ok_or_else(|| err(StatusCode::NOT_FOUND, "Organization not found"))
}

async fn require_admin(
    state: &AppState,
    headers: &Headers,
    org_id: &str,
) -> Result<Membership, (StatusCode, Json<Value>)> {
    let m = require_member(state, headers, org_id).await?;
    if m.atype > 1 {
        // owner=0, admin=1 → ok; user=2 / manager=3 / custom=4 → not authorized.
        return Err(err(StatusCode::FORBIDDEN, "Admin access required"));
    }
    Ok(m)
}

// --- Policies ---------------------------------------------------------------

#[worker::send]
async fn list_policies(
    AxumState(state): AxumState<AppState>,
    headers: Headers,
    Path(org_id): Path<String>,
) -> impl IntoResponse {
    if let Err(r) = require_member(&state, &headers, &org_id).await {
        return r;
    }
    let policies = OrgPolicy::find_by_org(&state.db, &org_id).await.unwrap_or_default();
    let data: Vec<Value> = policies.iter().map(policy_json).collect();
    (StatusCode::OK, Json(json!({ "Object": "list", "Data": data, "ContinuationToken": Value::Null })))
}

#[worker::send]
async fn get_policy(
    AxumState(state): AxumState<AppState>,
    headers: Headers,
    Path((org_id, atype)): Path<(String, i32)>,
) -> impl IntoResponse {
    if let Err(r) = require_member(&state, &headers, &org_id).await {
        return r;
    }
    match OrgPolicy::find_by_org_and_type(&state.db, &org_id, atype).await {
        Ok(Some(p)) => (StatusCode::OK, Json(policy_json(&p))),
        Ok(None) => (
            StatusCode::OK,
            Json(json!({
                "Object": "policy",
                "OrganizationId": org_id,
                "Type": atype,
                "Enabled": false,
                "Data": Value::Null,
            })),
        ),
        Err(_) => err(StatusCode::INTERNAL_SERVER_ERROR, "database error"),
    }
}

#[derive(Deserialize)]
struct PutPolicyBody {
    enabled: bool,
    #[serde(default, rename = "data")]
    data: Option<Value>,
}

#[worker::send]
async fn put_policy(
    AxumState(state): AxumState<AppState>,
    headers: Headers,
    Path((org_id, atype)): Path<(String, i32)>,
    Json(body): Json<PutPolicyBody>,
) -> impl IntoResponse {
    if let Err(r) = require_admin(&state, &headers, &org_id).await {
        return r;
    }
    let mut p = match OrgPolicy::find_by_org_and_type(&state.db, &org_id, atype).await {
        Ok(Some(p)) => p,
        Ok(None) => OrgPolicy::new(org_id.clone(), atype, "{}".into()),
        Err(_) => return err(StatusCode::INTERNAL_SERVER_ERROR, "database error"),
    };
    p.enabled = if body.enabled { 1 } else { 0 };
    p.data = body.data.map(|v| v.to_string()).unwrap_or_else(|| "{}".into());
    if p.save(&state.db).await.is_err() {
        return err(StatusCode::INTERNAL_SERVER_ERROR, "save failed");
    }
    crate::api::events::log_org_event(
        &state,
        crate::api::events::event_type::POLICY_UPDATED,
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
    (StatusCode::OK, Json(policy_json(&p)))
}

#[worker::send]
async fn master_password_policy(
    AxumState(state): AxumState<AppState>,
    headers: Headers,
    Path(org_id): Path<String>,
) -> impl IntoResponse {
    if let Err(r) = require_member(&state, &headers, &org_id).await {
        return r;
    }
    // Type 1 = MasterPassword in Bitwarden's PolicyType enum.
    match OrgPolicy::find_by_org_and_type(&state.db, &org_id, 1).await {
        Ok(Some(p)) if p.enabled == 1 => (StatusCode::OK, Json(policy_json(&p))),
        _ => (
            StatusCode::OK,
            Json(json!({
                "Object": "masterPasswordPolicy",
                "MinComplexity": 0,
                "MinLength": 0,
                "RequireUpper": false,
                "RequireLower": false,
                "RequireNumbers": false,
                "RequireSpecial": false,
                "EnforceOnLogin": false,
            })),
        ),
    }
}

#[worker::send]
async fn policies_by_token(
    AxumState(state): AxumState<AppState>,
    Path(org_id): Path<String>,
) -> impl IntoResponse {
    // Public endpoint — used during registration / SSO. We return the
    // full policy list; without an invite token we can't restrict by
    // recipient, so we just gate on the org existing.
    let policies = OrgPolicy::find_by_org(&state.db, &org_id).await.unwrap_or_default();
    let data: Vec<Value> = policies.iter().map(policy_json).collect();
    (StatusCode::OK, Json(json!({ "Object": "list", "Data": data, "ContinuationToken": Value::Null })))
}

// --- Groups -----------------------------------------------------------------

#[derive(Deserialize)]
struct GroupBody {
    name: String,
    #[serde(default, rename = "accessAll")]
    access_all: Option<bool>,
    #[serde(default, rename = "externalId")]
    external_id: Option<String>,
    /// List of membership UUIDs (not user UUIDs) to assign to the group.
    #[serde(default)]
    users: Option<Vec<String>>,
    /// Collection ACL entries: `{id, readOnly, hidePasswords, manage}`.
    #[serde(default)]
    collections: Option<Vec<GroupCollectionEntry>>,
}

#[derive(Deserialize)]
struct GroupCollectionEntry {
    id: String,
    #[serde(default, rename = "readOnly")]
    _read_only: bool,
    #[serde(default, rename = "hidePasswords")]
    _hide_passwords: bool,
    #[serde(default)]
    _manage: bool,
}

#[worker::send]
async fn list_groups(
    AxumState(state): AxumState<AppState>,
    headers: Headers,
    Path(org_id): Path<String>,
) -> impl IntoResponse {
    if let Err(r) = require_member(&state, &headers, &org_id).await {
        return r;
    }
    let groups = Group::find_by_org(&state.db, &org_id).await.unwrap_or_default();
    let data: Vec<Value> = groups.iter().map(group_json).collect();
    (StatusCode::OK, Json(json!({ "Object": "list", "Data": data, "ContinuationToken": Value::Null })))
}

#[worker::send]
async fn list_groups_details(
    AxumState(state): AxumState<AppState>,
    headers: Headers,
    Path(org_id): Path<String>,
) -> impl IntoResponse {
    if let Err(r) = require_member(&state, &headers, &org_id).await {
        return r;
    }
    let groups = Group::find_by_org(&state.db, &org_id).await.unwrap_or_default();
    let mut data: Vec<Value> = Vec::with_capacity(groups.len());
    for g in &groups {
        // Resolve the group's collection assignments. Upstream's
        // `/groups/details` shape inlines `Collections` so the web vault can
        // show "what does this group reach?" without a second round-trip.
        #[derive(serde::Deserialize)]
        struct CollRow {
            collections_uuid: String,
            read_only: i32,
            hide_passwords: i32,
            manage: i32,
        }
        let coll_rows: Vec<CollRow> = match state
            .db
            .prepare(
                "SELECT collections_uuid, read_only, hide_passwords, manage \
                 FROM collections_groups WHERE groups_uuid = ?1",
            )
            .bind(&[worker::wasm_bindgen::JsValue::from_str(&g.uuid)])
        {
            Ok(s) => s.all().await.ok().and_then(|r| r.results().ok()).unwrap_or_default(),
            Err(_) => Vec::new(),
        };
        let collections: Vec<Value> = coll_rows
            .into_iter()
            .map(|c| {
                json!({
                    "Id": c.collections_uuid,
                    "ReadOnly": c.read_only == 1,
                    "HidePasswords": c.hide_passwords == 1,
                    "Manage": c.manage == 1,
                })
            })
            .collect();
        let mut entry = group_json(g);
        if let Value::Object(ref mut map) = entry {
            map.insert("Collections".into(), Value::Array(collections));
        }
        data.push(entry);
    }
    (StatusCode::OK, Json(json!({ "Object": "list", "Data": data, "ContinuationToken": Value::Null })))
}

#[worker::send]
async fn post_group(
    AxumState(state): AxumState<AppState>,
    headers: Headers,
    Path(org_id): Path<String>,
    Json(body): Json<GroupBody>,
) -> impl IntoResponse {
    if let Err(r) = require_admin(&state, &headers, &org_id).await {
        return r;
    }
    let mut g = Group::new(org_id.clone(), body.name, body.access_all.unwrap_or(false));
    g.external_id = body.external_id;
    if g.save(&state.db).await.is_err() {
        return err(StatusCode::INTERNAL_SERVER_ERROR, "save failed");
    }
    if let Some(member_ids) = body.users {
        for member_id in member_ids {
            let _set = GroupUser::set(&state.db, &g.uuid, &member_id).await;
        }
    }
    if let Some(collection_entries) = body.collections {
        for entry in collection_entries {
            let bind = [
                worker::wasm_bindgen::JsValue::from_str(&entry.id),
                worker::wasm_bindgen::JsValue::from_str(&g.uuid),
            ];
            if let Ok(s) = state
                .db
                .prepare(
                    "INSERT OR IGNORE INTO collections_groups \
                     (collections_uuid, groups_uuid, read_only, hide_passwords) \
                     VALUES (?1, ?2, 0, 0)",
                )
                .bind(&bind)
            {
                let _r = s.run().await;
            }
        }
    }
    crate::api::events::log_org_event(
        &state,
        crate::api::events::event_type::GROUP_CREATED,
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
    (StatusCode::OK, Json(group_json(&g)))
}

#[worker::send]
async fn get_group(
    AxumState(state): AxumState<AppState>,
    headers: Headers,
    Path((org_id, group_id)): Path<(String, String)>,
) -> impl IntoResponse {
    if let Err(r) = require_member(&state, &headers, &org_id).await {
        return r;
    }
    match Group::find_by_uuid(&state.db, &group_id).await {
        Ok(Some(g)) if g.organizations_uuid == org_id => (StatusCode::OK, Json(group_json(&g))),
        _ => err(StatusCode::NOT_FOUND, "Group not found"),
    }
}

#[worker::send]
async fn get_group_details(
    AxumState(state): AxumState<AppState>,
    headers: Headers,
    Path((org_id, group_id)): Path<(String, String)>,
) -> impl IntoResponse {
    if let Err(r) = require_member(&state, &headers, &org_id).await {
        return r;
    }
    let g = match Group::find_by_uuid(&state.db, &group_id).await {
        Ok(Some(g)) if g.organizations_uuid == org_id => g,
        _ => return err(StatusCode::NOT_FOUND, "Group not found"),
    };
    #[derive(serde::Deserialize)]
    struct CollRow {
        collections_uuid: String,
        read_only: i32,
        hide_passwords: i32,
        manage: i32,
    }
    let coll_rows: Vec<CollRow> = match state
        .db
        .prepare(
            "SELECT collections_uuid, read_only, hide_passwords, manage \
             FROM collections_groups WHERE groups_uuid = ?1",
        )
        .bind(&[worker::wasm_bindgen::JsValue::from_str(&g.uuid)])
    {
        Ok(s) => s.all().await.ok().and_then(|r| r.results().ok()).unwrap_or_default(),
        Err(_) => Vec::new(),
    };
    let collections: Vec<Value> = coll_rows
        .into_iter()
        .map(|c| {
            json!({
                "Id": c.collections_uuid,
                "ReadOnly": c.read_only == 1,
                "HidePasswords": c.hide_passwords == 1,
                "Manage": c.manage == 1,
            })
        })
        .collect();
    let mut entry = group_json(&g);
    if let Value::Object(ref mut map) = entry {
        map.insert("Collections".into(), Value::Array(collections));
    }
    (StatusCode::OK, Json(entry))
}

#[worker::send]
async fn put_group(
    AxumState(state): AxumState<AppState>,
    headers: Headers,
    Path((org_id, group_id)): Path<(String, String)>,
    Json(body): Json<GroupBody>,
) -> impl IntoResponse {
    if let Err(r) = require_admin(&state, &headers, &org_id).await {
        return r;
    }
    let mut g = match Group::find_by_uuid(&state.db, &group_id).await {
        Ok(Some(g)) if g.organizations_uuid == org_id => g,
        _ => return err(StatusCode::NOT_FOUND, "Group not found"),
    };
    g.name = body.name;
    if let Some(a) = body.access_all {
        g.access_all = if a { 1 } else { 0 };
    }
    g.external_id = body.external_id;
    if g.save(&state.db).await.is_err() {
        return err(StatusCode::INTERNAL_SERVER_ERROR, "save failed");
    }
    if let Some(member_ids) = body.users {
        // Replace member set: drop existing, set new.
        let existing = GroupUser::list_by_group(&state.db, &g.uuid).await.unwrap_or_default();
        for m in existing {
            let _u = GroupUser::unset(&state.db, &g.uuid, &m).await;
        }
        for member_id in member_ids {
            let _set = GroupUser::set(&state.db, &g.uuid, &member_id).await;
        }
    }
    if let Some(collection_entries) = body.collections {
        let bind = [worker::wasm_bindgen::JsValue::from_str(&g.uuid)];
        if let Ok(s) = state
            .db
            .prepare("DELETE FROM collections_groups WHERE groups_uuid = ?1")
            .bind(&bind)
        {
            let _r = s.run().await;
        }
        for entry in collection_entries {
            let bind = [
                worker::wasm_bindgen::JsValue::from_str(&entry.id),
                worker::wasm_bindgen::JsValue::from_str(&g.uuid),
            ];
            if let Ok(s) = state
                .db
                .prepare(
                    "INSERT OR IGNORE INTO collections_groups \
                     (collections_uuid, groups_uuid, read_only, hide_passwords) \
                     VALUES (?1, ?2, 0, 0)",
                )
                .bind(&bind)
            {
                let _r = s.run().await;
            }
        }
    }
    crate::api::events::log_org_event(
        &state,
        crate::api::events::event_type::GROUP_UPDATED,
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
    (StatusCode::OK, Json(group_json(&g)))
}

#[worker::send]
async fn delete_group(
    AxumState(state): AxumState<AppState>,
    headers: Headers,
    Path((org_id, group_id)): Path<(String, String)>,
) -> impl IntoResponse {
    if let Err(r) = require_admin(&state, &headers, &org_id).await {
        return r;
    }
    let g = match Group::find_by_uuid(&state.db, &group_id).await {
        Ok(Some(g)) if g.organizations_uuid == org_id => g,
        _ => return err(StatusCode::NOT_FOUND, "Group not found"),
    };
    // Drop junction rows: members + collection ACLs hung off this group.
    let bind = worker::wasm_bindgen::JsValue::from_str(&group_id);
    for sql in [
        "DELETE FROM groups_users WHERE groups_uuid = ?1",
        "DELETE FROM collections_groups WHERE groups_uuid = ?1",
    ] {
        if let Ok(stmt) = state.db.prepare(sql).bind(&[bind.clone()]) {
            let _r = stmt.run().await;
        }
    }
    if g.delete(&state.db).await.is_err() {
        return err(StatusCode::INTERNAL_SERVER_ERROR, "delete failed");
    }
    crate::api::events::log_org_event(
        &state,
        crate::api::events::event_type::GROUP_DELETED,
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

#[derive(Deserialize)]
struct BulkGroupIds {
    #[serde(default)]
    ids: Vec<String>,
}

#[worker::send]
async fn bulk_delete_groups(
    AxumState(state): AxumState<AppState>,
    headers: Headers,
    Path(org_id): Path<String>,
    Json(body): Json<BulkGroupIds>,
) -> impl IntoResponse {
    if let Err(r) = require_admin(&state, &headers, &org_id).await {
        return r;
    }
    for id in body.ids {
        if let Ok(Some(g)) = Group::find_by_uuid(&state.db, &id).await
            && g.organizations_uuid == org_id
        {
            // Drop junction rows: members + collection ACLs hung off the group.
            let bind = worker::wasm_bindgen::JsValue::from_str(&id);
            for sql in [
                "DELETE FROM groups_users WHERE groups_uuid = ?1",
                "DELETE FROM collections_groups WHERE groups_uuid = ?1",
            ] {
                if let Ok(stmt) = state.db.prepare(sql).bind(&[bind.clone()]) {
                    let _r = stmt.run().await;
                }
            }
            let _del = g.delete(&state.db).await;
            crate::api::events::log_org_event(
                &state,
                crate::api::events::event_type::GROUP_DELETED,
                &org_id,
                &headers.user.uuid,
                None,
                headers.device.atype,
            )
            .await;
        }
    }
    (StatusCode::OK, Json(json!({})))
}

#[worker::send]
async fn group_users(
    AxumState(state): AxumState<AppState>,
    headers: Headers,
    Path((org_id, group_id)): Path<(String, String)>,
) -> impl IntoResponse {
    if let Err(r) = require_member(&state, &headers, &org_id).await {
        return r;
    }
    match Group::find_by_uuid(&state.db, &group_id).await {
        Ok(Some(g)) if g.organizations_uuid == org_id => {}
        _ => return err(StatusCode::NOT_FOUND, "Group not found"),
    }
    let members = GroupUser::list_by_group(&state.db, &group_id).await.unwrap_or_default();
    (StatusCode::OK, Json(json!(members)))
}

#[derive(Deserialize)]
struct SetGroupUsersBody(Vec<String>);

#[worker::send]
async fn set_group_users(
    AxumState(state): AxumState<AppState>,
    headers: Headers,
    Path((org_id, group_id)): Path<(String, String)>,
    Json(body): Json<SetGroupUsersBody>,
) -> impl IntoResponse {
    if let Err(r) = require_admin(&state, &headers, &org_id).await {
        return r;
    }
    // Confirm group lives in this org so we don't mutate state for an
    // unrelated group_id supplied on the path.
    match Group::find_by_uuid(&state.db, &group_id).await {
        Ok(Some(g)) if g.organizations_uuid == org_id => {}
        _ => return err(StatusCode::NOT_FOUND, "Group not found"),
    }
    // Replace the full set of memberships in the group.
    if let Ok(existing) = GroupUser::list_by_group(&state.db, &group_id).await {
        for member_id in existing {
            let _u = GroupUser::unset(&state.db, &group_id, &member_id).await;
        }
    }
    for member_id in body.0 {
        let _s = GroupUser::set(&state.db, &group_id, &member_id).await;
    }
    crate::api::events::log_org_event(
        &state,
        crate::api::events::event_type::GROUP_UPDATED,
        &org_id,
        &headers.user.uuid,
        None,
        headers.device.atype,
    )
    .await;
    (StatusCode::OK, Json(json!({})))
}

#[worker::send]
async fn remove_group_user(
    AxumState(state): AxumState<AppState>,
    headers: Headers,
    Path((org_id, group_id, member_id)): Path<(String, String, String)>,
) -> impl IntoResponse {
    if let Err(r) = require_admin(&state, &headers, &org_id).await {
        return r;
    }
    // Confirm group lives in this org so we don't accidentally mutate
    // unrelated state on a malformed path.
    match Group::find_by_uuid(&state.db, &group_id).await {
        Ok(Some(g)) if g.organizations_uuid == org_id => {}
        _ => return err(StatusCode::NOT_FOUND, "Group not found"),
    }
    let _u = GroupUser::unset(&state.db, &group_id, &member_id).await;
    crate::api::events::log_org_event(
        &state,
        crate::api::events::event_type::GROUP_UPDATED,
        &org_id,
        &headers.user.uuid,
        None,
        headers.device.atype,
    )
    .await;
    (StatusCode::OK, Json(json!({})))
}
