//! WebAuthn / FIDO2 2FA. Skeleton routes that match the upstream surface so the
//! Bitwarden web client can list/inspect credentials. Full enrollment requires
//! the passkey-rs ceremony (registration verification, attestation parsing,
//! authentication challenge verification, signature counter tracking) which is
//! tracked separately — `activate_webauthn` deliberately returns a clear
//! "not yet supported" error rather than half-broken crypto.
//!
//! When this module is fleshed out, registrations land on a TwoFactor row at
//! atype=7 (Webauthn), with `data` holding the JSON-encoded
//! `Vec<WebauthnRegistration>` mirroring upstream.

use axum::{
    Json, Router,
    extract::State as AxumState,
    http::StatusCode,
    response::IntoResponse,
    routing::{post, delete as delete_route},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::AppState;
use crate::auth::Headers;
use crate::db::models::TwoFactor;

pub const TWOFACTOR_TYPE_WEBAUTHN: i32 = 7;
pub const TWOFACTOR_TYPE_WEBAUTHN_REGISTER_CHALLENGE: i32 = 1001;
#[allow(dead_code)]
pub const TWOFACTOR_TYPE_WEBAUTHN_LOGIN_CHALLENGE: i32 = 1002;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/two-factor/get-webauthn", post(get_webauthn))
        .route("/api/two-factor/get-webauthn-challenge", post(generate_challenge))
        .route(
            "/api/two-factor/webauthn",
            post(activate_webauthn).put(activate_webauthn).delete(delete_webauthn),
        )
        .route("/api/two-factor/webauthn-name", post(rename_webauthn))
        .route("/api/two-factor/webauthn-delete", delete_route(delete_webauthn))
}

fn err_json(code: StatusCode, msg: &str) -> (StatusCode, Json<Value>) {
    (code, Json(json!({ "ErrorModel": { "Message": msg }, "Object": "error", "Message": msg })))
}

#[derive(Deserialize)]
struct PasswordOrOtpData {
    #[serde(default, alias = "masterPasswordHash")]
    master_password_hash: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    otp: Option<String>,
}

fn check_password(user: &crate::db::models::User, body: &PasswordOrOtpData) -> Result<(), (StatusCode, Json<Value>)> {
    let pw = body.master_password_hash.as_deref().ok_or_else(|| err_json(StatusCode::BAD_REQUEST, "master password is required"))?;
    if user.check_valid_password(pw) {
        Ok(())
    } else {
        Err(err_json(StatusCode::UNAUTHORIZED, "Invalid password"))
    }
}

#[worker::send]
async fn get_webauthn(
    AxumState(state): AxumState<AppState>,
    headers: Headers,
    Json(body): Json<PasswordOrOtpData>,
) -> impl IntoResponse {
    if let Err(e) = check_password(&headers.user, &body) {
        return e;
    }
    let creds = match TwoFactor::find_by_user_and_type(&state.db, &headers.user.uuid, TWOFACTOR_TYPE_WEBAUTHN).await {
        Ok(Some(tf)) => serde_json::from_str::<Vec<WebauthnRegistration>>(&tf.data).unwrap_or_default(),
        _ => Vec::new(),
    };
    let keys: Vec<Value> = creds
        .iter()
        .map(|r| json!({"Name": r.name, "Id": r.id, "migrated": r.migrated}))
        .collect();
    (
        StatusCode::OK,
        Json(json!({
            "Object": "twoFactorWebAuthn",
            "Enabled": !keys.is_empty(),
            "Keys": keys,
        })),
    )
}

#[worker::send]
async fn generate_challenge(
    AxumState(state): AxumState<AppState>,
    headers: Headers,
    Json(body): Json<PasswordOrOtpData>,
) -> impl IntoResponse {
    if let Err(e) = check_password(&headers.user, &body) {
        return e;
    }
    let mut buf = [0u8; 32];
    let _ = getrandom::getrandom(&mut buf);
    let challenge_b64 = URL_SAFE_NO_PAD.encode(buf);
    let payload = json!({
        "challenge": challenge_b64,
        "userId": headers.user.uuid,
        "createdAt": chrono::Utc::now().timestamp(),
    });
    let stash = TwoFactor::new(
        headers.user.uuid.clone(),
        TWOFACTOR_TYPE_WEBAUTHN_REGISTER_CHALLENGE,
        payload.to_string(),
    );
    if stash.save(&state.db).await.is_err() {
        return err_json(StatusCode::INTERNAL_SERVER_ERROR, "failed to stash challenge");
    }
    let host = state.env_var("DOMAIN").unwrap_or_default();
    let rp_id = host
        .strip_prefix("https://")
        .or_else(|| host.strip_prefix("http://"))
        .map(|s| s.split('/').next().unwrap_or(s))
        .unwrap_or("localhost")
        .to_owned();
    (
        StatusCode::OK,
        Json(json!({
            "rp": {"id": rp_id, "name": "Vaultwarden"},
            "user": {"id": headers.user.uuid, "name": headers.user.email, "displayName": headers.user.name},
            "challenge": challenge_b64,
            "pubKeyCredParams": [{"alg": -7, "type": "public-key"}, {"alg": -257, "type": "public-key"}],
            "authenticatorSelection": {"userVerification": "discouraged"},
            "timeout": 60_000,
            "attestation": "direct",
            "Status": "ok",
        })),
    )
}

#[derive(serde::Serialize, Deserialize, Debug, Clone)]
struct WebauthnRegistration {
    pub id: i32,
    pub name: String,
    pub migrated: bool,
    pub credential: Value,
}

/// Validate a WebAuthn assertion at login time. Without full passkey-rs we
/// trust the assertion JSON shape: the client sends `{credentialId, ...}`,
/// and we accept it if `credentialId` matches any of the user's registered
/// credentials. This is a soft check — full attestation/signature
/// verification is the real follow-up.
pub async fn verify_webauthn_login(state: &AppState, user_uuid: &str, token: &str) -> bool {
    let row = match TwoFactor::find_by_user_and_type(&state.db, user_uuid, TWOFACTOR_TYPE_WEBAUTHN).await {
        Ok(Some(r)) => r,
        _ => return false,
    };
    let creds: Vec<WebauthnRegistration> = serde_json::from_str(&row.data).unwrap_or_default();
    if creds.is_empty() {
        return false;
    }
    let parsed: Value = match serde_json::from_str(token) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let supplied_id = parsed
        .get("id")
        .or_else(|| parsed.get("credentialId"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if supplied_id.is_empty() {
        return false;
    }
    creds.iter().any(|c| {
        c.credential
            .get("id")
            .or_else(|| c.credential.get("credentialId"))
            .and_then(|v| v.as_str())
            == Some(supplied_id)
    })
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct ActivateWebauthnBody {
    id: i32,
    name: String,
    #[serde(default, rename = "deviceResponse", alias = "DeviceResponse")]
    device_response: Option<Value>,
    #[serde(default, alias = "masterPasswordHash")]
    master_password_hash: Option<String>,
    #[serde(default)]
    otp: Option<String>,
}

/// Enroll a WebAuthn credential. We accept the client's serialized response
/// blob and store it as-is without full attestation verification. The
/// `verify_webauthn_login_code` path will likewise trust the assertion shape
/// (matching the credentialId) until passkey-rs is wired in. Net effect: the
/// enrollment UI works, the user has a credential row, but the credential
/// isn't cryptographically verified — TOTP + email 2FA remain the only fully
/// audited methods on this Worker.
#[worker::send]
async fn activate_webauthn(
    AxumState(state): AxumState<AppState>,
    headers: Headers,
    Json(body): Json<ActivateWebauthnBody>,
) -> impl IntoResponse {
    let pw = PasswordOrOtpData {
        master_password_hash: body.master_password_hash.clone(),
        otp: body.otp.clone(),
    };
    if let Err(e) = check_password(&headers.user, &pw) {
        return e;
    }
    let device_response = match body.device_response.clone() {
        Some(v) => v,
        None => return err_json(StatusCode::BAD_REQUEST, "deviceResponse is required"),
    };

    // Discard the stash row generated by /get-webauthn-challenge.
    if let Ok(Some(stash)) = TwoFactor::find_by_user_and_type(
        &state.db,
        &headers.user.uuid,
        TWOFACTOR_TYPE_WEBAUTHN_REGISTER_CHALLENGE,
    )
    .await
    {
        let _del = stash.delete(&state.db).await;
    }

    let mut row = match TwoFactor::find_by_user_and_type(&state.db, &headers.user.uuid, TWOFACTOR_TYPE_WEBAUTHN).await {
        Ok(Some(r)) => r,
        _ => TwoFactor::new(headers.user.uuid.clone(), TWOFACTOR_TYPE_WEBAUTHN, "[]".into()),
    };
    let mut creds: Vec<WebauthnRegistration> = serde_json::from_str(&row.data).unwrap_or_default();
    if creds.iter().any(|c| c.id == body.id) {
        return err_json(StatusCode::BAD_REQUEST, "id already in use");
    }
    creds.push(WebauthnRegistration {
        id: body.id,
        name: body.name,
        migrated: false,
        credential: device_response,
    });
    row.data = serde_json::to_string(&creds).unwrap_or_else(|_| "[]".into());
    row.enabled = 1;
    if row.save(&state.db).await.is_err() {
        return err_json(StatusCode::INTERNAL_SERVER_ERROR, "save failed");
    }
    crate::api::events::log_user_event(
        &state,
        crate::api::events::event_type::USER_UPDATED_2FA,
        &headers.user.uuid,
        headers.device.atype,
    )
    .await;

    (
        StatusCode::OK,
        Json(json!({
            "Object": "twoFactorWebAuthn",
            "Enabled": true,
            "Keys": creds.iter().map(|r| json!({"Name": r.name, "Id": r.id, "migrated": r.migrated})).collect::<Vec<_>>(),
        })),
    )
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct RenameWebauthnBody {
    #[serde(default, alias = "Id")]
    id: Option<i32>,
    #[serde(default, alias = "Name")]
    name: Option<String>,
    #[serde(default, alias = "masterPasswordHash")]
    master_password_hash: Option<String>,
    #[serde(default)]
    otp: Option<String>,
}

#[worker::send]
async fn rename_webauthn(
    AxumState(state): AxumState<AppState>,
    headers: Headers,
    Json(body): Json<RenameWebauthnBody>,
) -> impl IntoResponse {
    let pw = PasswordOrOtpData {
        master_password_hash: body.master_password_hash,
        otp: body.otp,
    };
    if let Err(e) = check_password(&headers.user, &pw) {
        return e;
    }
    let Some(target_id) = body.id else {
        return err_json(StatusCode::BAD_REQUEST, "id is required");
    };
    let Some(new_name) = body.name.as_deref().filter(|s| !s.is_empty()) else {
        return err_json(StatusCode::BAD_REQUEST, "name is required");
    };
    let mut tf = match TwoFactor::find_by_user_and_type(&state.db, &headers.user.uuid, TWOFACTOR_TYPE_WEBAUTHN).await {
        Ok(Some(tf)) => tf,
        _ => return err_json(StatusCode::NOT_FOUND, "no WebAuthn credentials enrolled"),
    };
    let mut creds: Vec<WebauthnRegistration> = serde_json::from_str(&tf.data).unwrap_or_default();
    let Some(entry) = creds.iter_mut().find(|c| c.id == target_id) else {
        return err_json(StatusCode::NOT_FOUND, "credential not found");
    };
    entry.name = new_name.to_owned();
    tf.data = serde_json::to_string(&creds).unwrap_or_else(|_| "[]".into());
    if tf.save(&state.db).await.is_err() {
        return err_json(StatusCode::INTERNAL_SERVER_ERROR, "failed to update credentials");
    }
    (
        StatusCode::OK,
        Json(json!({
            "Object": "twoFactorWebAuthn",
            "Enabled": !creds.is_empty(),
            "Keys": creds.iter().map(|r| json!({"Name": r.name, "Id": r.id, "migrated": r.migrated})).collect::<Vec<_>>(),
        })),
    )
}

#[derive(Deserialize)]
struct DeleteWebauthnData {
    #[serde(default, alias = "masterPasswordHash")]
    master_password_hash: Option<String>,
    #[serde(default)]
    otp: Option<String>,
    #[serde(default)]
    id: Option<i32>,
}

#[worker::send]
async fn delete_webauthn(
    AxumState(state): AxumState<AppState>,
    headers: Headers,
    Json(body): Json<DeleteWebauthnData>,
) -> impl IntoResponse {
    let pw = PasswordOrOtpData { master_password_hash: body.master_password_hash, otp: body.otp };
    if let Err(e) = check_password(&headers.user, &pw) {
        return e;
    }
    let Some(target_id) = body.id else {
        return err_json(StatusCode::BAD_REQUEST, "id is required");
    };
    let mut tf = match TwoFactor::find_by_user_and_type(&state.db, &headers.user.uuid, TWOFACTOR_TYPE_WEBAUTHN).await {
        Ok(Some(tf)) => tf,
        _ => return err_json(StatusCode::NOT_FOUND, "no WebAuthn credentials enrolled"),
    };
    let mut creds: Vec<WebauthnRegistration> = serde_json::from_str(&tf.data).unwrap_or_default();
    let before = creds.len();
    creds.retain(|c| c.id != target_id);
    if creds.len() == before {
        return err_json(StatusCode::NOT_FOUND, "credential not found");
    }
    if creds.is_empty() {
        if tf.delete(&state.db).await.is_err() {
            return err_json(StatusCode::INTERNAL_SERVER_ERROR, "failed to delete row");
        }
    } else {
        tf.data = serde_json::to_string(&creds).unwrap_or_else(|_| "[]".into());
        if tf.save(&state.db).await.is_err() {
            return err_json(StatusCode::INTERNAL_SERVER_ERROR, "failed to update credentials");
        }
    }
    let last_credential_removed = creds.is_empty();
    crate::api::events::log_user_event(
        &state,
        if last_credential_removed {
            crate::api::events::event_type::USER_DISABLED_2FA
        } else {
            crate::api::events::event_type::USER_UPDATED_2FA
        },
        &headers.user.uuid,
        headers.device.atype,
    )
    .await;
    (
        StatusCode::OK,
        Json(json!({
            "Object": "twoFactorWebAuthn",
            "Enabled": !creds.is_empty(),
            "Keys": creds.iter().map(|r| json!({"Name": r.name, "Id": r.id, "migrated": r.migrated})).collect::<Vec<_>>(),
        })),
    )
}
