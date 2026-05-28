//! Event log endpoints.
//!
//! Mirrors upstream's surface so admin clients showing the audit log work:
//! GET /api/organizations/{id}/events, /api/ciphers/{id}/events,
//! /api/organizations/{id}/users/{member_id}/events, and POST /api/collect
//! for client-emitted events. The `event` table already exists.

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
use crate::db::models::{Event, Membership};

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/organizations/{org_id}/events", get(org_events))
        .route("/api/ciphers/{cipher_id}/events", get(cipher_events))
        .route(
            "/api/organizations/{org_id}/users/{member_id}/events",
            get(member_events),
        )
        .route("/api/collect", post(collect_events))
        .route("/api/organizations/{org_id}/collect", post(collect_events))
}

fn err_json(code: StatusCode, msg: &str) -> (StatusCode, Json<Value>) {
    (code, Json(json!({ "ErrorModel": { "Message": msg }, "Object": "error", "Message": msg })))
}

fn event_json(e: &Event) -> Value {
    json!({
        "Object": "event",
        "Type": e.event_type,
        "UserId": e.user_uuid,
        "OrganizationId": e.org_uuid,
        "CipherId": e.cipher_uuid,
        "CollectionId": e.collection_uuid,
        "GroupId": e.group_uuid,
        "OrganizationUserId": e.org_user_uuid,
        "ActingUserId": e.act_user_uuid,
        "DeviceType": e.device_type,
        "IpAddress": e.ip_address,
        "Date": e.event_date,
        "PolicyId": e.policy_uuid,
        "ProviderId": e.provider_uuid,
    })
}

fn list(events: Vec<Event>) -> (StatusCode, Json<Value>) {
    let data: Vec<Value> = events.iter().map(event_json).collect();
    (StatusCode::OK, Json(json!({ "Object": "list", "Data": data, "ContinuationToken": Value::Null })))
}

#[derive(Deserialize)]
struct EventQuery {
    #[serde(default)]
    start: Option<String>,
    #[serde(default)]
    end: Option<String>,
    #[serde(default, rename = "continuationToken")]
    _continuation_token: Option<String>,
}

fn default_event_range(q: &EventQuery) -> (String, String) {
    let now = chrono::Utc::now();
    let end = q
        .end
        .clone()
        .unwrap_or_else(|| now.to_rfc3339_opts(chrono::SecondsFormat::Micros, true));
    let start = q
        .start
        .clone()
        .unwrap_or_else(|| (now - chrono::Duration::days(30)).to_rfc3339_opts(chrono::SecondsFormat::Micros, true));
    (start, end)
}

#[worker::send]
async fn org_events(
    AxumState(state): AxumState<AppState>,
    headers: Headers,
    Path(org_id): Path<String>,
    axum::extract::Query(q): axum::extract::Query<EventQuery>,
) -> impl IntoResponse {
    if Membership::find_by_user_and_org(&state.db, &headers.user.uuid, &org_id)
        .await
        .ok()
        .flatten()
        .is_none()
    {
        return err_json(StatusCode::NOT_FOUND, "Organization not found");
    }
    let (start, end) = default_event_range(&q);
    list(Event::find_by_org_in_range(&state.db, &org_id, &start, &end).await.unwrap_or_default())
}

#[worker::send]
async fn cipher_events(
    AxumState(state): AxumState<AppState>,
    headers: Headers,
    Path(cipher_id): Path<String>,
    axum::extract::Query(q): axum::extract::Query<EventQuery>,
) -> impl IntoResponse {
    let cipher = match crate::db::models::Cipher::find_by_uuid(&state.db, &cipher_id).await {
        Ok(Some(c)) => c,
        _ => return err_json(StatusCode::NOT_FOUND, "Cipher not found"),
    };
    let visible = if let Some(uid) = cipher.user_uuid.as_deref() {
        uid == headers.user.uuid
    } else if let Some(org) = cipher.organization_uuid.as_deref() {
        Membership::find_by_user_and_org(&state.db, &headers.user.uuid, org)
            .await
            .ok()
            .flatten()
            .is_some()
    } else {
        false
    };
    if !visible {
        return err_json(StatusCode::NOT_FOUND, "Cipher not found");
    }
    let (start, end) = default_event_range(&q);
    list(Event::find_by_cipher_in_range(&state.db, &cipher_id, &start, &end).await.unwrap_or_default())
}

#[worker::send]
async fn member_events(
    AxumState(state): AxumState<AppState>,
    headers: Headers,
    Path((org_id, member_id)): Path<(String, String)>,
    axum::extract::Query(q): axum::extract::Query<EventQuery>,
) -> impl IntoResponse {
    if Membership::find_by_user_and_org(&state.db, &headers.user.uuid, &org_id)
        .await
        .ok()
        .flatten()
        .is_none()
    {
        return err_json(StatusCode::NOT_FOUND, "Organization not found");
    }
    let target = match Membership::find_by_uuid(&state.db, &member_id).await {
        Ok(Some(m)) if m.org_uuid == org_id => m,
        _ => return err_json(StatusCode::NOT_FOUND, "Membership not found"),
    };
    let (start, end) = default_event_range(&q);
    list(Event::find_by_user_in_range(&state.db, &target.user_uuid, &start, &end).await.unwrap_or_default())
}

#[derive(Deserialize)]
struct CollectEvent {
    #[serde(rename = "type", alias = "Type")]
    atype: i32,
    #[serde(default, rename = "cipherId", alias = "CipherId")]
    cipher_id: Option<String>,
    #[serde(default, rename = "organizationId", alias = "OrganizationId")]
    org_id: Option<String>,
    #[serde(default)]
    date: Option<String>,
}

#[worker::send]
async fn collect_events(
    AxumState(state): AxumState<AppState>,
    headers: Headers,
    Json(events): Json<Vec<CollectEvent>>,
) -> impl IntoResponse {
    for ce in events {
        let mut e = Event::new(ce.atype);
        e.user_uuid = Some(headers.user.uuid.clone());
        e.act_user_uuid = Some(headers.user.uuid.clone());
        e.cipher_uuid = ce.cipher_id;
        e.org_uuid = ce.org_id;
        e.device_type = Some(headers.device.atype);
        if let Some(d) = ce.date {
            e.event_date = d;
        }
        let _result = e.save(&state.db).await;
    }
    (StatusCode::OK, Json(json!({})))
}

// EventType enum values that mutation handlers emit. Mirrors upstream's
// `EventType` so the admin audit log surface is interchangeable. Numeric
// values must match upstream `src/db/models/event.rs` exactly — the values
// surface raw to the admin UI.
#[allow(dead_code)]
pub mod event_type {
    // User (1000–1099)
    pub const USER_LOGGED_IN: i32 = 1000;
    pub const USER_CHANGED_PASSWORD: i32 = 1001;
    pub const USER_UPDATED_2FA: i32 = 1002;
    pub const USER_DISABLED_2FA: i32 = 1003;
    pub const USER_RECOVERED_2FA: i32 = 1004;
    pub const USER_LOGGED_IN_FAILED: i32 = 1005; // UserFailedLogIn
    pub const USER_LOGGED_IN_FAILED_2FA: i32 = 1006;
    pub const USER_CLIENT_EXPORTED_VAULT: i32 = 1007;
    pub const USER_REQUESTED_DEVICE_APPROVAL: i32 = 1010;
    // Aliases retained for the existing emit-sites — upstream uses
    // UserChangedPassword for password rotations.
    pub const USER_UPDATED_PASSWORD: i32 = USER_CHANGED_PASSWORD;
    pub const USER_UPDATED_KDF: i32 = USER_CHANGED_PASSWORD;

    // Cipher (1100–1199)
    pub const CIPHER_CREATED: i32 = 1100;
    pub const CIPHER_UPDATED: i32 = 1101;
    pub const CIPHER_DELETED: i32 = 1102;
    pub const CIPHER_ATTACHMENT_CREATED: i32 = 1103;
    pub const CIPHER_ATTACHMENT_DELETED: i32 = 1104;
    pub const CIPHER_SHARED: i32 = 1105;
    pub const CIPHER_UPDATED_COLLECTIONS: i32 = 1106;
    pub const CIPHER_SOFT_DELETED: i32 = 1115;
    pub const CIPHER_RESTORED: i32 = 1116;

    // Collections + groups
    pub const COLLECTION_CREATED: i32 = 1300;
    pub const COLLECTION_UPDATED: i32 = 1301;
    pub const COLLECTION_DELETED: i32 = 1302;
    pub const GROUP_CREATED: i32 = 1400;
    pub const GROUP_UPDATED: i32 = 1401;
    pub const GROUP_DELETED: i32 = 1402;

    // Org user
    pub const ORG_USER_INVITED: i32 = 1500;
    pub const ORG_USER_CONFIRMED: i32 = 1501;
    pub const ORG_USER_UPDATED: i32 = 1502;
    pub const ORG_USER_REMOVED: i32 = 1503;
    pub const ORG_USER_UPDATED_GROUPS: i32 = 1504;
    pub const ORG_USER_UNLINKED_SSO: i32 = 1505;
    pub const ORG_USER_RESET_PASSWORD_ENROLL: i32 = 1506;
    pub const ORG_USER_RESET_PASSWORD_WITHDRAW: i32 = 1507;
    pub const ORG_USER_ADMIN_RESET_PASSWORD: i32 = 1508;
    pub const ORG_USER_REVOKED: i32 = 1511;
    pub const ORG_USER_RESTORED: i32 = 1512;
    pub const ORG_USER_DELETED: i32 = 1515;
    pub const ORG_USER_LEFT: i32 = 1516;

    // Organization (1600–1699)
    pub const ORG_UPDATED: i32 = 1600;
    pub const ORG_PURGED_VAULT: i32 = 1601;
    pub const ORG_CLIENT_EXPORTED_VAULT: i32 = 1602;

    // Policy
    pub const POLICY_UPDATED: i32 = 1700;
}

/// Best-effort: log a user-scoped event. Errors are swallowed because
/// the audit log is observability-only — a write failure must not fail
/// the underlying mutation.
#[allow(dead_code)]
pub async fn log_user_event(
    state: &AppState,
    event_type: i32,
    user_uuid: &str,
    device_type: i32,
) {
    let mut e = Event::new(event_type);
    e.user_uuid = Some(user_uuid.to_owned());
    e.act_user_uuid = Some(user_uuid.to_owned());
    e.device_type = Some(device_type);
    let _save = e.save(&state.db).await;
}

/// Best-effort: log a cipher-scoped event with the optional org link.
#[allow(dead_code)]
pub async fn log_cipher_event(
    state: &AppState,
    event_type: i32,
    cipher_uuid: &str,
    user_uuid: &str,
    org_uuid: Option<&str>,
    device_type: i32,
) {
    let mut e = Event::new(event_type);
    e.cipher_uuid = Some(cipher_uuid.to_owned());
    e.user_uuid = Some(user_uuid.to_owned());
    e.act_user_uuid = Some(user_uuid.to_owned());
    e.org_uuid = org_uuid.map(str::to_owned);
    e.device_type = Some(device_type);
    let _save = e.save(&state.db).await;
}

/// Best-effort: log an org-scoped event (member changes, settings, etc).
#[allow(dead_code)]
pub async fn log_org_event(
    state: &AppState,
    event_type: i32,
    org_uuid: &str,
    actor_uuid: &str,
    target_member: Option<&str>,
    device_type: i32,
) {
    let mut e = Event::new(event_type);
    e.org_uuid = Some(org_uuid.to_owned());
    e.act_user_uuid = Some(actor_uuid.to_owned());
    e.org_user_uuid = target_member.map(str::to_owned);
    e.device_type = Some(device_type);
    let _save = e.save(&state.db).await;
}
