//! Helpers for fanning out vault-mutation notifications to a user's
//! connected WebSocket clients via the `UserNotificationDO` Durable Object.

use serde_json::json;

use crate::AppState;

#[allow(dead_code)]
pub mod kind {
    pub const SYNC_CIPHER_UPDATE: i32 = 0;
    pub const SYNC_CIPHER_CREATE: i32 = 1;
    pub const SYNC_LOGIN_DELETE: i32 = 2;
    pub const SYNC_FOLDER_DELETE: i32 = 3;
    pub const SYNC_CIPHERS: i32 = 4;
    pub const SYNC_VAULT: i32 = 5;
    pub const SYNC_ORG_KEYS: i32 = 6;
    pub const SYNC_FOLDER_CREATE: i32 = 7;
    pub const SYNC_FOLDER_UPDATE: i32 = 8;
    pub const SYNC_CIPHER_DELETE: i32 = 9;
    pub const SYNC_SETTINGS: i32 = 10;
    pub const LOG_OUT: i32 = 11;
    pub const SYNC_SEND_CREATE: i32 = 12;
    pub const SYNC_SEND_UPDATE: i32 = 13;
    pub const SYNC_SEND_DELETE: i32 = 14;
}

#[allow(dead_code)]
pub async fn notify_user(state: &AppState, user_uuid: &str, kind: i32, payload_id: &str) {
    let body = json!({
        "Type": kind,
        "Payload": { "Id": payload_id, "UserId": user_uuid, "RevisionDate": now_iso() },
        "ContextId": null,
    });
    let _result = send_to_user_do(state, user_uuid, body.to_string()).await;
}

/// Fan out an org-scoped notification to every confirmed member by hitting
/// each member's UserNotificationDO. Used when org-wide state changes (member
/// added/removed, org renamed, collection added/removed) so all clients pick
/// up the change without polling /sync.
#[allow(dead_code)]
pub async fn notify_org(state: &AppState, org_uuid: &str, kind: i32, payload_id: &str) {
    use crate::db::models::Membership;

    // STATUS_CONFIRMED == 2; only confirmed members can see org content.
    const STATUS_CONFIRMED: i32 = 2;
    let members = match Membership::find_by_org(&state.db, org_uuid).await {
        Ok(m) => m,
        Err(_) => return,
    };
    for m in members.into_iter().filter(|m| m.status == STATUS_CONFIRMED) {
        notify_user(state, &m.user_uuid, kind, payload_id).await;
    }
}

async fn send_to_user_do(state: &AppState, user_uuid: &str, body: String) -> worker::Result<()> {
    let ns = state.user_notifications.as_ref();
    let id = ns.id_from_name(user_uuid)?;
    let stub = id.get_stub()?;
    let mut req_init = worker::RequestInit::new();
    req_init.with_method(worker::Method::Post).with_body(Some(body.into()));
    let req = worker::Request::new_with_init("https://do/broadcast", &req_init)?;
    let _resp = stub.fetch_with_request(req).await?;
    Ok(())
}

/// Push an "auth request response" event to whichever DO is fronting the
/// passwordless-login anonymous hub for this token. The DO key is the
/// auth-request UUID itself; the AnonymousNotificationDO namespace keeps
/// these conns separate from per-user fan-out.
#[allow(dead_code)]
pub async fn notify_anon(state: &AppState, token: &str, payload_id: &str) {
    let body = serde_json::json!({
        "Type": 16, // AuthRequestResponse — Bitwarden's enum value
        "Payload": { "Id": payload_id, "RevisionDate": now_iso() },
        "ContextId": null,
    });
    let ns = state.anon_notifications.as_ref();
    let id = match ns.id_from_name(token) {
        Ok(i) => i,
        Err(_) => return,
    };
    let stub = match id.get_stub() {
        Ok(s) => s,
        Err(_) => return,
    };
    let mut req_init = worker::RequestInit::new();
    req_init.with_method(worker::Method::Post).with_body(Some(body.to_string().into()));
    if let Ok(req) = worker::Request::new_with_init("https://do/broadcast", &req_init) {
        let _resp = stub.fetch_with_request(req).await;
    }
}

fn now_iso() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Micros, true)
}
