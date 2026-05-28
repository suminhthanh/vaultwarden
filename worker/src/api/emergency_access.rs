//! Emergency access endpoints.
//!
//! A grantor invites a grantee to be their emergency contact. The grantee can
//! later "initiate" access; after `wait_time_days`, they can take over the
//! grantor's account (or just view it). Status flow:
//!
//!   0 Invited  → 1 Accepted → 2 Confirmed → 3 RecoveryInitiated → 4 RecoveryApproved
//!
//! Type: 0 = View, 1 = Takeover.
//!
//! We don't ship any of the cron-driven timeout logic yet — the grantee has to
//! explicitly call /approve. Mirrors upstream's HTTP surface; the wait-window
//! enforcement is intentionally deferred (logged as a follow-up task).

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
use crate::db::models::{EmergencyAccess, User};

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/emergency-access/trusted", get(list_trusted))
        .route("/api/emergency-access/granted", get(list_granted))
        .route("/api/emergency-access/{id}", get(get_access).put(update_access).post(update_access).delete(delete_access))
        .route("/api/emergency-access/{id}/delete", post(delete_access))
        .route("/api/emergency-access/invite", post(invite))
        .route("/api/emergency-access/{id}/reinvite", post(reinvite))
        .route("/api/emergency-access/{id}/accept", post(accept))
        .route("/api/emergency-access/{id}/confirm", post(confirm))
        .route("/api/emergency-access/{id}/initiate", post(initiate))
        .route("/api/emergency-access/{id}/approve", post(approve))
        .route("/api/emergency-access/{id}/reject", post(reject))
        .route("/api/emergency-access/{id}/view", post(view))
        .route("/api/emergency-access/{id}/takeover", post(takeover))
        .route("/api/emergency-access/{id}/password", post(takeover_password))
        .route("/api/emergency-access/{id}/policies", get(policies))
}

const STATUS_INVITED: i32 = 0;
const STATUS_ACCEPTED: i32 = 1;
const STATUS_CONFIRMED: i32 = 2;
const STATUS_RECOVERY_INITIATED: i32 = 3;
const STATUS_RECOVERY_APPROVED: i32 = 4;

const TYPE_VIEW: i32 = 0;
const TYPE_TAKEOVER: i32 = 1;

fn err(code: StatusCode, msg: &str) -> (StatusCode, Json<Value>) {
    (code, Json(json!({ "ErrorModel": { "Message": msg }, "Object": "error", "Message": msg })))
}

fn json_ea(e: &EmergencyAccess) -> Value {
    json!({
        "Object": "emergencyAccess",
        "Id": e.uuid,
        "GrantorId": e.grantor_uuid,
        "GranteeId": e.grantee_uuid,
        "Email": e.email,
        "Type": e.atype,
        "Status": e.status,
        "WaitTimeDays": e.wait_time_days,
        "KeyEncrypted": e.key_encrypted,
        "RecoveryInitiatedDate": e.recovery_initiated_at,
        "LastNotificationDate": e.last_notification_at,
        "RevisionDate": e.updated_at,
        "CreationDate": e.created_at,
    })
}

/// Like `json_ea` but inlines the grantor/grantee profile fields the web vault
/// renders for the trusted/granted lists. Upstream's `to_json_grantor_details`
/// and `to_json_grantee_details` both use this exact shape.
async fn json_ea_with_grantor_details(state: &AppState, e: &EmergencyAccess) -> Value {
    let mut v = json_ea(e);
    if let Some(uuid) = e.grantor_uuid.as_deref()
        && let Ok(Some(u)) = User::find_by_uuid(&state.db, uuid).await
    {
        if let Value::Object(ref mut map) = v {
            map.insert("GrantorName".into(), Value::String(u.name));
            map.insert("GrantorEmail".into(), Value::String(u.email));
            map.insert("GrantorAvatarColor".into(), match u.avatar_color {
                Some(c) => Value::String(c),
                None => Value::Null,
            });
        }
    }
    v
}

async fn json_ea_with_grantee_details(state: &AppState, e: &EmergencyAccess) -> Value {
    let mut v = json_ea(e);
    if let Some(uuid) = e.grantee_uuid.as_deref()
        && let Ok(Some(u)) = User::find_by_uuid(&state.db, uuid).await
    {
        if let Value::Object(ref mut map) = v {
            map.insert("GranteeName".into(), Value::String(u.name));
            map.insert("GranteeEmail".into(), Value::String(u.email.clone()));
            map.insert("Email".into(), Value::String(u.email));
            map.insert("GranteeAvatarColor".into(), match u.avatar_color {
                Some(c) => Value::String(c),
                None => Value::Null,
            });
        }
    }
    v
}

#[worker::send]
async fn list_trusted(AxumState(state): AxumState<AppState>, headers: Headers) -> impl IntoResponse {
    let rows = EmergencyAccess::find_by_grantor(&state.db, &headers.user.uuid).await.unwrap_or_default();
    let mut data = Vec::with_capacity(rows.len());
    for e in &rows {
        data.push(json_ea_with_grantee_details(&state, e).await);
    }
    (StatusCode::OK, Json(json!({ "Object": "list", "Data": data, "ContinuationToken": Value::Null })))
}

#[worker::send]
async fn list_granted(AxumState(state): AxumState<AppState>, headers: Headers) -> impl IntoResponse {
    let rows = EmergencyAccess::find_by_grantee(&state.db, &headers.user.uuid).await.unwrap_or_default();
    let mut data = Vec::with_capacity(rows.len());
    for e in &rows {
        data.push(json_ea_with_grantor_details(&state, e).await);
    }
    (StatusCode::OK, Json(json!({ "Object": "list", "Data": data, "ContinuationToken": Value::Null })))
}

async fn load(state: &AppState, id: &str) -> Result<EmergencyAccess, (StatusCode, Json<Value>)> {
    EmergencyAccess::find_by_uuid(&state.db, id)
        .await
        .ok()
        .flatten()
        .ok_or_else(|| err(StatusCode::NOT_FOUND, "Emergency access not found"))
}

fn assert_grantor(e: &EmergencyAccess, headers: &Headers) -> Result<(), (StatusCode, Json<Value>)> {
    if e.grantor_uuid.as_deref() == Some(headers.user.uuid.as_str()) {
        Ok(())
    } else {
        Err(err(StatusCode::FORBIDDEN, "Not the grantor"))
    }
}

fn assert_grantee(e: &EmergencyAccess, headers: &Headers) -> Result<(), (StatusCode, Json<Value>)> {
    if e.grantee_uuid.as_deref() == Some(headers.user.uuid.as_str()) {
        Ok(())
    } else {
        Err(err(StatusCode::FORBIDDEN, "Not the grantee"))
    }
}

#[worker::send]
async fn get_access(
    AxumState(state): AxumState<AppState>,
    headers: Headers,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let e = match load(&state, &id).await {
        Ok(e) => e,
        Err(r) => return r,
    };
    let is_grantor = e.grantor_uuid.as_deref() == Some(headers.user.uuid.as_str());
    let is_grantee = e.grantee_uuid.as_deref() == Some(headers.user.uuid.as_str());
    if !is_grantor && !is_grantee {
        return err(StatusCode::FORBIDDEN, "Not your emergency access record");
    }
    let body = if is_grantor {
        // Grantor sees the grantee's email (the contact they trusted).
        json_ea_with_grantee_details(&state, &e).await
    } else {
        // Grantee sees the grantor's name + email (the account they may take over).
        json_ea_with_grantor_details(&state, &e).await
    };
    (StatusCode::OK, Json(body))
}

#[derive(Deserialize)]
struct UpdateBody {
    #[serde(default, rename = "type")]
    atype: Option<i32>,
    #[serde(default, rename = "waitTimeDays")]
    wait_time_days: Option<i32>,
}

#[worker::send]
async fn update_access(
    AxumState(state): AxumState<AppState>,
    headers: Headers,
    Path(id): Path<String>,
    Json(body): Json<UpdateBody>,
) -> impl IntoResponse {
    let mut e = match load(&state, &id).await {
        Ok(e) => e,
        Err(r) => return r,
    };
    if let Err(r) = assert_grantor(&e, &headers) {
        return r;
    }
    if let Some(t) = body.atype {
        e.atype = t;
    }
    if let Some(d) = body.wait_time_days {
        e.wait_time_days = d.max(1);
    }
    if e.save(&state.db).await.is_err() {
        return err(StatusCode::INTERNAL_SERVER_ERROR, "save failed");
    }
    (StatusCode::OK, Json(json_ea(&e)))
}

#[worker::send]
async fn delete_access(
    AxumState(state): AxumState<AppState>,
    headers: Headers,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let e = match load(&state, &id).await {
        Ok(e) => e,
        Err(r) => return r,
    };
    if e.grantor_uuid.as_deref() != Some(headers.user.uuid.as_str())
        && e.grantee_uuid.as_deref() != Some(headers.user.uuid.as_str())
    {
        return err(StatusCode::FORBIDDEN, "Not your emergency access record");
    }
    if e.delete(&state.db).await.is_err() {
        return err(StatusCode::INTERNAL_SERVER_ERROR, "delete failed");
    }
    (StatusCode::OK, Json(json!({})))
}

#[derive(Deserialize)]
struct InviteBody {
    email: String,
    #[serde(rename = "type")]
    atype: i32,
    #[serde(rename = "waitTimeDays")]
    wait_time_days: i32,
}

#[worker::send]
async fn invite(
    AxumState(state): AxumState<AppState>,
    headers: Headers,
    Json(body): Json<InviteBody>,
) -> impl IntoResponse {
    let email = body.email.trim().to_lowercase();
    if email == headers.user.email {
        return err(StatusCode::BAD_REQUEST, "Cannot grant emergency access to yourself");
    }
    // Rate-limit on the inviter so a hostile user can't spam strangers' inboxes.
    if !crate::ratelimit::check(
        &state.ratelimit_kv,
        &crate::ratelimit::EMAIL_SEND_LIMIT,
        &headers.user.uuid,
    )
    .await
    {
        return err(StatusCode::TOO_MANY_REQUESTS, "Too many invitations");
    }
    let mut e = EmergencyAccess::new(body.atype, STATUS_INVITED, body.wait_time_days.max(1));
    e.grantor_uuid = Some(headers.user.uuid.clone());
    e.email = Some(email.clone());
    if let Ok(Some(grantee)) = User::find_by_email(&state.db, &email).await {
        e.grantee_uuid = Some(grantee.uuid);
    }
    if e.save(&state.db).await.is_err() {
        return err(StatusCode::INTERNAL_SERVER_ERROR, "save failed");
    }
    let (from_email, from_name) = state.mail_from.as_ref().clone();
    let _send = state
        .mail
        .send(&crate::mail::MailMessage {
            from_email,
            from_name,
            to: email,
            subject: "You have been invited as an emergency contact".into(),
            text: format!(
                "{} invited you as an emergency contact. Open Vaultwarden to accept.\n\nID: {}",
                headers.user.email, e.uuid,
            ),
            html: None,
        })
        .await;
    (StatusCode::OK, Json(json_ea(&e)))
}

#[worker::send]
async fn reinvite(
    AxumState(state): AxumState<AppState>,
    headers: Headers,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let e = match load(&state, &id).await {
        Ok(e) => e,
        Err(r) => return r,
    };
    if let Err(r) = assert_grantor(&e, &headers) {
        return r;
    }
    if let Some(addr) = e.email.clone() {
        let (from_email, from_name) = state.mail_from.as_ref().clone();
        let _send = state
            .mail
            .send(&crate::mail::MailMessage {
                from_email,
                from_name,
                to: addr,
                subject: "Reminder: emergency access invitation".into(),
                text: format!("Reminder. ID: {}", e.uuid),
                html: None,
            })
            .await;
    }
    (StatusCode::OK, Json(json!({})))
}

#[worker::send]
async fn accept(
    AxumState(state): AxumState<AppState>,
    headers: Headers,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let mut e = match load(&state, &id).await {
        Ok(e) => e,
        Err(r) => return r,
    };
    if e.email.as_deref() != Some(headers.user.email.as_str()) {
        return err(StatusCode::FORBIDDEN, "Not the invited email");
    }
    e.grantee_uuid = Some(headers.user.uuid.clone());
    if e.status == STATUS_INVITED {
        e.status = STATUS_ACCEPTED;
    }
    if e.save(&state.db).await.is_err() {
        return err(StatusCode::INTERNAL_SERVER_ERROR, "save failed");
    }
    (StatusCode::OK, Json(json_ea(&e)))
}

#[derive(Deserialize)]
struct ConfirmBody {
    /// Encrypted user key for the grantee (RSA-encrypted with grantee's public key).
    key: String,
}

#[worker::send]
async fn confirm(
    AxumState(state): AxumState<AppState>,
    headers: Headers,
    Path(id): Path<String>,
    Json(body): Json<ConfirmBody>,
) -> impl IntoResponse {
    let mut e = match load(&state, &id).await {
        Ok(e) => e,
        Err(r) => return r,
    };
    if let Err(r) = assert_grantor(&e, &headers) {
        return r;
    }
    if e.status != STATUS_ACCEPTED {
        return err(StatusCode::BAD_REQUEST, "Emergency access not in accepted state");
    }
    e.key_encrypted = Some(body.key);
    e.status = STATUS_CONFIRMED;
    if e.save(&state.db).await.is_err() {
        return err(StatusCode::INTERNAL_SERVER_ERROR, "save failed");
    }
    (StatusCode::OK, Json(json_ea(&e)))
}

#[worker::send]
async fn initiate(
    AxumState(state): AxumState<AppState>,
    headers: Headers,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let mut e = match load(&state, &id).await {
        Ok(e) => e,
        Err(r) => return r,
    };
    if let Err(r) = assert_grantee(&e, &headers) {
        return r;
    }
    if e.status != STATUS_CONFIRMED {
        return err(StatusCode::BAD_REQUEST, "Emergency access not in confirmed state");
    }
    e.status = STATUS_RECOVERY_INITIATED;
    e.recovery_initiated_at = Some(chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Micros, true));
    if e.save(&state.db).await.is_err() {
        return err(StatusCode::INTERNAL_SERVER_ERROR, "save failed");
    }
    // Email the grantor so they know recovery has started and can approve or
    // reject before the wait window elapses.
    if let Some(grantor_uuid) = e.grantor_uuid.as_deref()
        && let Ok(Some(grantor)) = User::find_by_uuid(&state.db, grantor_uuid).await
    {
        let (from_email, from_name) = state.mail_from.as_ref().clone();
        let _send = state
            .mail
            .send(&crate::mail::MailMessage {
                from_email,
                from_name,
                to: grantor.email.clone(),
                subject: "Emergency access recovery initiated".into(),
                text: format!(
                    "{} has initiated emergency access recovery. \
                     They will gain {} after {} day(s) unless you approve or reject in Vaultwarden.\n\nID: {}",
                    headers.user.email,
                    if e.atype == TYPE_TAKEOVER { "takeover" } else { "view" },
                    e.wait_time_days,
                    e.uuid,
                ),
                html: None,
            })
            .await;
    }
    (StatusCode::OK, Json(json_ea(&e)))
}

#[worker::send]
async fn approve(
    AxumState(state): AxumState<AppState>,
    headers: Headers,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let mut e = match load(&state, &id).await {
        Ok(e) => e,
        Err(r) => return r,
    };
    if let Err(r) = assert_grantor(&e, &headers) {
        return r;
    }
    if e.status != STATUS_RECOVERY_INITIATED {
        return err(StatusCode::BAD_REQUEST, "Recovery has not been initiated");
    }
    e.status = STATUS_RECOVERY_APPROVED;
    if e.save(&state.db).await.is_err() {
        return err(StatusCode::INTERNAL_SERVER_ERROR, "save failed");
    }
    // Notify the grantee that they may now use takeover or view.
    if let Some(grantee_uuid) = e.grantee_uuid.as_deref()
        && let Ok(Some(grantee)) = User::find_by_uuid(&state.db, grantee_uuid).await
    {
        let (from_email, from_name) = state.mail_from.as_ref().clone();
        let _send = state
            .mail
            .send(&crate::mail::MailMessage {
                from_email,
                from_name,
                to: grantee.email,
                subject: "Emergency access recovery approved".into(),
                text: format!(
                    "{} approved your emergency access recovery. ID: {}",
                    headers.user.email, e.uuid,
                ),
                html: None,
            })
            .await;
    }
    (StatusCode::OK, Json(json_ea(&e)))
}

#[worker::send]
async fn reject(
    AxumState(state): AxumState<AppState>,
    headers: Headers,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let mut e = match load(&state, &id).await {
        Ok(e) => e,
        Err(r) => return r,
    };
    if let Err(r) = assert_grantor(&e, &headers) {
        return r;
    }
    if !matches!(e.status, STATUS_RECOVERY_INITIATED | STATUS_RECOVERY_APPROVED) {
        return err(StatusCode::BAD_REQUEST, "Recovery is not pending");
    }
    e.status = STATUS_CONFIRMED;
    if e.save(&state.db).await.is_err() {
        return err(StatusCode::INTERNAL_SERVER_ERROR, "save failed");
    }
    if let Some(grantee_uuid) = e.grantee_uuid.as_deref()
        && let Ok(Some(grantee)) = User::find_by_uuid(&state.db, grantee_uuid).await
    {
        let (from_email, from_name) = state.mail_from.as_ref().clone();
        let _send = state
            .mail
            .send(&crate::mail::MailMessage {
                from_email,
                from_name,
                to: grantee.email,
                subject: "Emergency access recovery rejected".into(),
                text: format!(
                    "{} rejected your emergency access recovery. ID: {}",
                    headers.user.email, e.uuid,
                ),
                html: None,
            })
            .await;
    }
    (StatusCode::OK, Json(json_ea(&e)))
}

#[worker::send]
async fn view(
    AxumState(state): AxumState<AppState>,
    headers: Headers,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let e = match load(&state, &id).await {
        Ok(e) => e,
        Err(r) => return r,
    };
    if let Err(r) = assert_grantee(&e, &headers) {
        return r;
    }
    if e.atype != TYPE_VIEW || e.status != STATUS_RECOVERY_APPROVED {
        return err(StatusCode::FORBIDDEN, "Recovery not approved or not a view grant");
    }
    let grantor = match e.grantor_uuid.as_deref() {
        Some(uuid) => User::find_by_uuid(&state.db, uuid).await.ok().flatten(),
        None => None,
    };
    let grantor_key = grantor.as_ref().map(|g| g.akey.clone()).unwrap_or_default();
    let ciphers = match grantor.as_ref() {
        Some(g) => crate::db::models::Cipher::find_owned_by_user(&state.db, &g.uuid)
            .await
            .unwrap_or_default(),
        None => Vec::new(),
    };
    let cipher_jsons: Vec<Value> = ciphers
        .iter()
        .map(|c| crate::api::ciphers::cipher_to_json_full(c, false, &[], None))
        .collect();
    (
        StatusCode::OK,
        Json(json!({
            "Object": "emergencyAccessView",
            "KeyEncrypted": e.key_encrypted,
            "GrantorKey": grantor_key,
            "Ciphers": cipher_jsons,
        })),
    )
}

#[worker::send]
async fn takeover(
    AxumState(state): AxumState<AppState>,
    headers: Headers,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let e = match load(&state, &id).await {
        Ok(e) => e,
        Err(r) => return r,
    };
    if let Err(r) = assert_grantee(&e, &headers) {
        return r;
    }
    if e.atype != TYPE_TAKEOVER || e.status != STATUS_RECOVERY_APPROVED {
        return err(StatusCode::FORBIDDEN, "Recovery not approved or not a takeover grant");
    }
    let grantor = match e.grantor_uuid.as_deref() {
        Some(uuid) => User::find_by_uuid(&state.db, uuid).await.ok().flatten(),
        None => None,
    };
    let g = match grantor {
        Some(u) => u,
        None => return err(StatusCode::NOT_FOUND, "Grantor missing"),
    };
    (
        StatusCode::OK,
        Json(json!({
            "Object": "emergencyAccessTakeover",
            "Kdf": g.client_kdf_type,
            "KdfIterations": g.client_kdf_iter,
            "KdfMemory": g.client_kdf_memory,
            "KdfParallelism": g.client_kdf_parallelism,
            "KeyEncrypted": e.key_encrypted,
        })),
    )
}

#[derive(Deserialize)]
struct TakeoverPasswordBody {
    #[serde(rename = "newMasterPasswordHash")]
    new_master_password_hash: String,
    key: String,
}

#[worker::send]
async fn takeover_password(
    AxumState(state): AxumState<AppState>,
    headers: Headers,
    Path(id): Path<String>,
    Json(body): Json<TakeoverPasswordBody>,
) -> impl IntoResponse {
    let e = match load(&state, &id).await {
        Ok(e) => e,
        Err(r) => return r,
    };
    if let Err(r) = assert_grantee(&e, &headers) {
        return r;
    }
    if e.atype != TYPE_TAKEOVER || e.status != STATUS_RECOVERY_APPROVED {
        return err(StatusCode::FORBIDDEN, "Recovery not approved");
    }
    let grantor_uuid = match e.grantor_uuid.clone() {
        Some(u) => u,
        None => return err(StatusCode::NOT_FOUND, "Grantor missing"),
    };
    let mut grantor = match User::find_by_uuid(&state.db, &grantor_uuid).await {
        Ok(Some(u)) => u,
        _ => return err(StatusCode::NOT_FOUND, "Grantor missing"),
    };
    grantor.set_password(&body.new_master_password_hash);
    grantor.akey = body.key;
    grantor.security_stamp = uuid::Uuid::new_v4().to_string();
    if grantor.save(&state.db).await.is_err() {
        return err(StatusCode::INTERNAL_SERVER_ERROR, "save failed");
    }
    // Force every device the grantor was logged in on to re-prompt — their
    // password just rotated.
    crate::api::notify::notify_user(
        &state,
        &grantor.uuid,
        crate::api::notify::kind::LOG_OUT,
        &grantor.uuid,
    )
    .await;
    crate::api::events::log_user_event(
        &state,
        crate::api::events::event_type::USER_CHANGED_PASSWORD,
        &grantor.uuid,
        headers.device.atype,
    )
    .await;
    state.telemetry.record(
        "emergency_takeover_password",
        &[("grantor", &grantor.uuid), ("grantee", &headers.user.uuid)],
    );
    (StatusCode::OK, Json(json!({})))
}

#[worker::send]
async fn policies(
    AxumState(state): AxumState<AppState>,
    headers: Headers,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let e = match load(&state, &id).await {
        Ok(e) => e,
        Err(r) => return r,
    };
    if let Err(r) = assert_grantee(&e, &headers) {
        return r;
    }
    // Upstream returns the master password policies of the grantor's orgs.
    // We don't ship policies yet, so return an empty list. Behaviour parity:
    // the client treats no policies as "do whatever".
    (StatusCode::OK, Json(json!({ "Object": "list", "Data": [], "ContinuationToken": Value::Null })))
}
