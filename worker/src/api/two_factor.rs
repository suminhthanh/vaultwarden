use axum::{
    Json, Router,
    extract::State as AxumState,
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
};
use data_encoding::BASE32_NOPAD;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use subtle::ConstantTimeEq;

use crate::AppState;
use crate::auth::Headers;
use crate::db::models::{TwoFactor, User};

pub const TWOFACTOR_TYPE_AUTHENTICATOR: i32 = 0;
pub const TWOFACTOR_TYPE_EMAIL: i32 = 1;
#[allow(dead_code)]
pub const TWOFACTOR_TYPE_RECOVERY: i32 = 2;
/// Per-device "remember 2FA" token row. Stored on the user's TwoFactor table
/// with `data` = a per-device token. Presence of a matching row lets the
/// password grant skip the 2FA challenge for that device.
pub const TWOFACTOR_TYPE_REMEMBER: i32 = 5;
pub const TWOFACTOR_TYPE_EMAIL_VERIFICATION_CHALLENGE: i32 = 1000;

const EMAIL_TOKEN_LEN: usize = 6;
const EMAIL_TOKEN_TTL_SECS: i64 = 600;
#[allow(dead_code)]
const EMAIL_ATTEMPT_LIMIT: u32 = 3;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/two-factor", get(list_methods))
        .route("/api/two-factor/get-authenticator", post(get_authenticator))
        .route(
            "/api/two-factor/authenticator",
            post(activate_authenticator)
                .put(activate_authenticator)
                .delete(disable_authenticator),
        )
        .route("/api/two-factor/disable", post(disable_method).put(disable_method))
        // Email 2FA
        .route("/api/two-factor/get-email", post(get_email_2fa))
        .route("/api/two-factor/send-email", post(send_email_2fa))
        .route("/api/two-factor/email", axum::routing::put(activate_email_2fa))
        .route("/api/two-factor/send-email-login", post(send_email_login))
        // Recovery
        .route("/api/two-factor/get-recover", post(get_recover))
        .route("/api/two-factor/recover", post(recover))
        // Device verification settings — bool stub
        .route("/api/two-factor/get-device-verification-settings", get(device_verification_settings))
        // Duo + YubiKey — stubs that match upstream's response so the client UI
        // doesn't error out. Real Duo/YubiKey enrolment is tracked separately.
        .route("/api/two-factor/get-duo", post(get_duo_stub))
        .route("/api/two-factor/duo", post(duo_unsupported).put(duo_unsupported))
        .route("/api/two-factor/get-yubikey", post(get_yubikey_stub))
        .route("/api/two-factor/yubikey", post(yubikey_unsupported).put(yubikey_unsupported))
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

fn check_password_or_otp(user: &User, body: &PasswordOrOtpData) -> Result<(), (StatusCode, Json<Value>)> {
    let password = body
        .master_password_hash
        .as_deref()
        .ok_or_else(|| err_json(StatusCode::BAD_REQUEST, "master password is required"))?;
    if user.check_valid_password(password) {
        Ok(())
    } else {
        Err(err_json(StatusCode::UNAUTHORIZED, "Invalid password"))
    }
}

fn random_b32_secret() -> String {
    let mut buf = [0u8; 20];
    let _ = getrandom::getrandom(&mut buf);
    BASE32_NOPAD.encode(&buf)
}

#[worker::send]
async fn list_methods(
    AxumState(state): AxumState<AppState>,
    headers: Headers,
) -> impl IntoResponse {
    let factors = TwoFactor::find_by_user(&state.db, &headers.user.uuid).await.unwrap_or_default();
    let data: Vec<Value> = factors
        .iter()
        .map(|f| json!({ "Object": "twoFactorProvider", "Enabled": f.enabled == 1, "Type": f.atype }))
        .collect();
    (StatusCode::OK, Json(json!({ "Object": "list", "Data": data, "ContinuationToken": Value::Null })))
}

#[worker::send]
async fn get_authenticator(
    AxumState(state): AxumState<AppState>,
    headers: Headers,
    Json(body): Json<PasswordOrOtpData>,
) -> impl IntoResponse {
    if let Err(e) = check_password_or_otp(&headers.user, &body) {
        return e;
    }

    let existing =
        TwoFactor::find_by_user_and_type(&state.db, &headers.user.uuid, TWOFACTOR_TYPE_AUTHENTICATOR)
            .await
            .unwrap_or(None);
    let (enabled, key) = match existing {
        Some(tf) => (tf.enabled == 1, tf.data),
        None => (false, random_b32_secret()),
    };

    (
        StatusCode::OK,
        Json(json!({
            "Object": "twoFactorAuthenticator",
            "Enabled": enabled,
            "Key": key,
        })),
    )
}

#[derive(Deserialize)]
struct EnableAuthenticatorData {
    key: String,
    token: String,
    #[serde(default, alias = "masterPasswordHash")]
    master_password_hash: Option<String>,
    #[serde(default)]
    otp: Option<String>,
}

fn totp_at(secret_b32: &str, time: u64) -> Option<String> {
    let key = BASE32_NOPAD.decode(secret_b32.as_bytes()).ok()?;
    Some(totp_lite::totp_custom::<totp_lite::Sha1>(30, 6, &key, time))
}

pub fn verify_totp_code(secret_b32: &str, code: &str) -> bool {
    verify_totp(secret_b32, code)
}

fn verify_totp(secret_b32: &str, code: &str) -> bool {
    let now: u64 = worker::Date::now().as_millis() / 1000;
    // ±1 step (30s) tolerance — matches upstream's drift behavior.
    for delta in [-1i64, 0, 1] {
        let t = now.saturating_add_signed(delta * 30);
        if let Some(expected) = totp_at(secret_b32, t)
            && expected.as_bytes().ct_eq(code.as_bytes()).into()
        {
            return true;
        }
    }
    false
}

#[worker::send]
async fn activate_authenticator(
    AxumState(state): AxumState<AppState>,
    headers: Headers,
    Json(body): Json<EnableAuthenticatorData>,
) -> impl IntoResponse {
    let pw_check = PasswordOrOtpData { master_password_hash: body.master_password_hash, otp: body.otp };
    if let Err(e) = check_password_or_otp(&headers.user, &pw_check) {
        return e;
    }

    let key_upper = body.key.to_ascii_uppercase();
    let decoded = match BASE32_NOPAD.decode(key_upper.as_bytes()) {
        Ok(d) => d,
        Err(_) => return err_json(StatusCode::BAD_REQUEST, "Invalid totp secret"),
    };
    if decoded.len() != 20 {
        return err_json(StatusCode::BAD_REQUEST, "Invalid key length");
    }
    if !verify_totp(&key_upper, body.token.trim()) {
        return err_json(StatusCode::BAD_REQUEST, "Invalid TOTP code");
    }

    let tf = TwoFactor::new(headers.user.uuid.clone(), TWOFACTOR_TYPE_AUTHENTICATOR, key_upper.clone());
    if tf.save(&state.db).await.is_err() {
        return err_json(StatusCode::INTERNAL_SERVER_ERROR, "failed to save 2FA");
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
            "Object": "twoFactorAuthenticator",
            "Enabled": true,
            "Key": key_upper,
        })),
    )
}

#[worker::send]
async fn disable_authenticator(
    AxumState(state): AxumState<AppState>,
    headers: Headers,
    Json(body): Json<PasswordOrOtpData>,
) -> impl IntoResponse {
    if let Err(e) = check_password_or_otp(&headers.user, &body) {
        return e;
    }
    if let Ok(Some(tf)) =
        TwoFactor::find_by_user_and_type(&state.db, &headers.user.uuid, TWOFACTOR_TYPE_AUTHENTICATOR).await
        && tf.delete(&state.db).await.is_err()
    {
        return err_json(StatusCode::INTERNAL_SERVER_ERROR, "failed to disable");
    }
    crate::api::events::log_user_event(
        &state,
        crate::api::events::event_type::USER_DISABLED_2FA,
        &headers.user.uuid,
        headers.device.atype,
    )
    .await;
    (
        StatusCode::OK,
        Json(json!({
            "Object": "twoFactorProvider",
            "Type": TWOFACTOR_TYPE_AUTHENTICATOR,
            "Enabled": false,
        })),
    )
}

#[derive(Deserialize)]
struct DisableMethodData {
    #[serde(rename = "type")]
    atype: i32,
    #[serde(default, alias = "masterPasswordHash")]
    master_password_hash: Option<String>,
    #[serde(default)]
    otp: Option<String>,
}

#[worker::send]
async fn disable_method(
    AxumState(state): AxumState<AppState>,
    headers: Headers,
    Json(body): Json<DisableMethodData>,
) -> impl IntoResponse {
    let pw_check = PasswordOrOtpData { master_password_hash: body.master_password_hash, otp: body.otp };
    if let Err(e) = check_password_or_otp(&headers.user, &pw_check) {
        return e;
    }
    if let Ok(Some(tf)) = TwoFactor::find_by_user_and_type(&state.db, &headers.user.uuid, body.atype).await
        && tf.delete(&state.db).await.is_err()
    {
        return err_json(StatusCode::INTERNAL_SERVER_ERROR, "failed to disable");
    }
    crate::api::events::log_user_event(
        &state,
        crate::api::events::event_type::USER_DISABLED_2FA,
        &headers.user.uuid,
        headers.device.atype,
    )
    .await;
    (
        StatusCode::OK,
        Json(json!({ "Object": "twoFactorProvider", "Type": body.atype, "Enabled": false })),
    )
}

// ---------------------------------------------------------------------------
// Email 2FA. Stored as JSON in the `twofactor` row's `data` column. Atype on
// the row is `1` (Email) once verified, `1000` (EmailVerificationChallenge)
// while waiting for the user to enter the verification code.

#[derive(Serialize, Deserialize)]
struct EmailTokenData {
    email: String,
    last_token: Option<String>,
    token_sent: i64,
    attempts: u32,
}

impl EmailTokenData {
    fn new(email: String, token: String) -> Self {
        Self { email, last_token: Some(token), token_sent: now_ts(), attempts: 0 }
    }
    fn from_json(s: &str) -> Option<Self> {
        serde_json::from_str(s).ok()
    }
    fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| "{}".into())
    }
    fn set_token(&mut self, token: String) {
        self.last_token = Some(token);
        self.token_sent = now_ts();
        self.attempts = 0;
    }
    fn reset_token(&mut self) {
        self.last_token = None;
        self.attempts = 0;
    }
    fn token_expired(&self) -> bool {
        now_ts() - self.token_sent > EMAIL_TOKEN_TTL_SECS
    }
}

fn now_ts() -> i64 {
    (worker::Date::now().as_millis() / 1000) as i64
}

fn random_email_token() -> String {
    let mut buf = [0u8; 4];
    let _ = getrandom::getrandom(&mut buf);
    let n = u32::from_be_bytes(buf) % 1_000_000;
    format!("{n:0width$}", width = EMAIL_TOKEN_LEN)
}

/// Send the email-2FA verification code via the configured mail provider.
/// Returns Ok(()) when the message was accepted by the provider; the LogProvider
/// (dev default) records and returns Ok so the local flow stays usable.
async fn send_email_token(state: &AppState, to: &str, token: &str) -> Result<(), String> {
    let (from_email, from_name) = state.mail_from.as_ref().clone();
    let text = format!(
        "Your Vaultwarden two-factor login code is {token}.\n\nIt expires in 10 minutes.",
    );
    state
        .mail
        .send(&crate::mail::MailMessage {
            from_email,
            from_name,
            to: to.to_owned(),
            subject: "Your Vaultwarden login code".into(),
            text,
            html: None,
        })
        .await
        .map_err(|e| e.to_string())
}

#[worker::send]
async fn get_email_2fa(
    AxumState(state): AxumState<AppState>,
    headers: Headers,
    Json(body): Json<PasswordOrOtpData>,
) -> impl IntoResponse {
    if let Err(e) = check_password_or_otp(&headers.user, &body) {
        return e;
    }
    let (enabled, email) =
        match TwoFactor::find_by_user_and_type(&state.db, &headers.user.uuid, TWOFACTOR_TYPE_EMAIL).await {
            Ok(Some(tf)) => match EmailTokenData::from_json(&tf.data) {
                Some(d) => (tf.enabled == 1, Value::String(d.email)),
                None => (false, Value::Null),
            },
            _ => (false, Value::Null),
        };
    (
        StatusCode::OK,
        Json(json!({
            "Object": "twoFactorEmail",
            "Enabled": enabled,
            "Email": email,
        })),
    )
}

#[derive(Deserialize)]
struct SendEmailData {
    email: String,
    #[serde(default, alias = "masterPasswordHash")]
    master_password_hash: Option<String>,
    #[serde(default)]
    otp: Option<String>,
}

#[worker::send]
async fn send_email_2fa(
    AxumState(state): AxumState<AppState>,
    headers: Headers,
    Json(body): Json<SendEmailData>,
) -> impl IntoResponse {
    let pw_check = PasswordOrOtpData { master_password_hash: body.master_password_hash, otp: body.otp };
    if let Err(e) = check_password_or_otp(&headers.user, &pw_check) {
        return e;
    }
    let target = body.email.trim().to_owned();
    if target.is_empty() {
        return err_json(StatusCode::BAD_REQUEST, "email is required");
    }
    if !crate::ratelimit::check(&state.ratelimit_kv, &crate::ratelimit::EMAIL_SEND_LIMIT, &target).await {
        return err_json(StatusCode::TOO_MANY_REQUESTS, "Too many email requests");
    }

    if let Ok(Some(tf)) =
        TwoFactor::find_by_user_and_type(&state.db, &headers.user.uuid, TWOFACTOR_TYPE_EMAIL).await
        && tf.delete(&state.db).await.is_err()
    {
        return err_json(StatusCode::INTERNAL_SERVER_ERROR, "failed to reset email 2FA");
    }
    if let Ok(Some(tf)) = TwoFactor::find_by_user_and_type(
        &state.db,
        &headers.user.uuid,
        TWOFACTOR_TYPE_EMAIL_VERIFICATION_CHALLENGE,
    )
    .await
        && tf.delete(&state.db).await.is_err()
    {
        return err_json(StatusCode::INTERNAL_SERVER_ERROR, "failed to reset challenge");
    }

    let token = random_email_token();
    let data = EmailTokenData::new(target.clone(), token.clone());
    let tf = TwoFactor::new(
        headers.user.uuid.clone(),
        TWOFACTOR_TYPE_EMAIL_VERIFICATION_CHALLENGE,
        data.to_json(),
    );
    if tf.save(&state.db).await.is_err() {
        return err_json(StatusCode::INTERNAL_SERVER_ERROR, "failed to save challenge");
    }
    if let Err(e) = send_email_token(&state, &target, &token).await {
        state.telemetry.record("email_2fa_send_failed", &[("err", &e)]);
        return err_json(StatusCode::INTERNAL_SERVER_ERROR, "failed to send verification email");
    }
    (StatusCode::OK, Json(Value::Null))
}

#[derive(Deserialize)]
struct ActivateEmailData {
    email: String,
    token: String,
    #[serde(default, alias = "masterPasswordHash")]
    master_password_hash: Option<String>,
    #[serde(default)]
    otp: Option<String>,
}

#[worker::send]
async fn activate_email_2fa(
    AxumState(state): AxumState<AppState>,
    headers: Headers,
    Json(body): Json<ActivateEmailData>,
) -> impl IntoResponse {
    let pw_check = PasswordOrOtpData { master_password_hash: body.master_password_hash, otp: body.otp };
    if let Err(e) = check_password_or_otp(&headers.user, &pw_check) {
        return e;
    }
    let mut tf = match TwoFactor::find_by_user_and_type(
        &state.db,
        &headers.user.uuid,
        TWOFACTOR_TYPE_EMAIL_VERIFICATION_CHALLENGE,
    )
    .await
    {
        Ok(Some(tf)) => tf,
        _ => return err_json(StatusCode::BAD_REQUEST, "no email verification in progress"),
    };
    let mut data = match EmailTokenData::from_json(&tf.data) {
        Some(d) => d,
        None => return err_json(StatusCode::BAD_REQUEST, "challenge data corrupt"),
    };
    if data.email != body.email.trim() {
        return err_json(StatusCode::BAD_REQUEST, "email mismatch");
    }
    let issued = match data.last_token.as_deref() {
        Some(t) => t.to_owned(),
        None => return err_json(StatusCode::BAD_REQUEST, "no token issued"),
    };
    if data.token_expired() {
        data.reset_token();
        tf.data = data.to_json();
        let _save = tf.save(&state.db).await;
        return err_json(StatusCode::BAD_REQUEST, "Token expired");
    }
    if !bool::from(issued.as_bytes().ct_eq(body.token.trim().as_bytes())) {
        return err_json(StatusCode::BAD_REQUEST, "Token is invalid");
    }

    data.reset_token();
    tf.data = data.to_json();
    tf.atype = TWOFACTOR_TYPE_EMAIL;
    tf.enabled = 1;
    if tf.save(&state.db).await.is_err() {
        return err_json(StatusCode::INTERNAL_SERVER_ERROR, "failed to save 2FA");
    }
    let mut user = headers.user.clone();
    let _recover = ensure_recovery_code(&state, &mut user).await;
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
            "Object": "twoFactorEmail",
            "Enabled": true,
            "Email": data.email,
        })),
    )
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct SendEmailLoginData {
    #[serde(default, alias = "Email")]
    email: Option<String>,
    #[serde(default, alias = "MasterPasswordHash")]
    master_password_hash: Option<String>,
    #[serde(default, alias = "DeviceIdentifier")]
    device_identifier: Option<String>,
}

#[worker::send]
async fn send_email_login(
    AxumState(state): AxumState<AppState>,
    Json(body): Json<SendEmailLoginData>,
) -> impl IntoResponse {
    let email = match body.email.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        Some(s) => s.to_owned(),
        None => return err_json(StatusCode::BAD_REQUEST, "email is required"),
    };
    if !crate::ratelimit::check(&state.ratelimit_kv, &crate::ratelimit::EMAIL_SEND_LIMIT, &email).await {
        return err_json(StatusCode::TOO_MANY_REQUESTS, "Too many email requests");
    }
    let user = match User::find_by_email(&state.db, &email).await {
        Ok(Some(u)) => u,
        _ => return (StatusCode::OK, Json(Value::Null)),
    };
    if let Some(mph) = body.master_password_hash.as_deref()
        && !user.check_valid_password(mph)
    {
        return (StatusCode::OK, Json(Value::Null));
    }
    if let Err(e) = send_login_token(&state, &user.uuid).await {
        state.telemetry.record("email_2fa_login_send_failed", &[("err", &e)]);
        return err_json(StatusCode::INTERNAL_SERVER_ERROR, "failed to send login email");
    }
    (StatusCode::OK, Json(Value::Null))
}

/// Generate a fresh login challenge for the given user's email-2FA row and
/// dispatch it. Used by `send_email_login` and by the identity flow when a
/// password grant resolves to email-2FA.
pub async fn send_login_token(state: &AppState, user_uuid: &str) -> Result<(), String> {
    if !crate::ratelimit::check(&state.ratelimit_kv, &crate::ratelimit::EMAIL_SEND_LIMIT, user_uuid).await {
        return Err("rate-limited".to_owned());
    }
    let mut tf = TwoFactor::find_by_user_and_type(&state.db, user_uuid, TWOFACTOR_TYPE_EMAIL)
        .await
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "Email 2FA is not enabled for this user".to_owned())?;
    let mut data =
        EmailTokenData::from_json(&tf.data).ok_or_else(|| "email 2FA data corrupt".to_owned())?;
    let token = random_email_token();
    data.set_token(token.clone());
    tf.data = data.to_json();
    tf.save(&state.db).await.map_err(|e| e.to_string())?;
    send_email_token(state, &data.email, &token).await
}

/// Verify a login-flow YubiKey OTP. The token is the 44-char OTP. We look up
/// the user's enrolled YubiKey row, confirm the token's 12-char prefix is one
/// of the registered keys, then ask Yubico's API to verify.
pub async fn verify_yubikey_login_code(
    state: &AppState,
    user_uuid: &str,
    token: &str,
) -> bool {
    if token.len() != 44 {
        return false;
    }
    let row = match TwoFactor::find_by_user_and_type(&state.db, user_uuid, TWOFACTOR_TYPE_YUBIKEY).await {
        Ok(Some(r)) => r,
        _ => return false,
    };
    let meta: YubikeyMetadata = match serde_json::from_str(&row.data) {
        Ok(m) => m,
        Err(_) => return false,
    };
    let prefix = &token[..12];
    if !meta.keys.iter().any(|k| k == prefix) {
        return false;
    }
    verify_yubikey_otp(state, token).await.is_ok()
}

/// Verify a login-flow email 2FA code. Mutates the row to invalidate the token
/// on success, or to record an attempt on failure.
pub async fn verify_email_login_code(state: &AppState, user_uuid: &str, code: &str) -> bool {
    let mut tf = match TwoFactor::find_by_user_and_type(&state.db, user_uuid, TWOFACTOR_TYPE_EMAIL).await {
        Ok(Some(tf)) => tf,
        _ => return false,
    };
    let mut data = match EmailTokenData::from_json(&tf.data) {
        Some(d) => d,
        None => return false,
    };
    let issued = match data.last_token.clone() {
        Some(t) => t,
        None => return false,
    };
    if data.token_expired() {
        data.reset_token();
        tf.data = data.to_json();
        let _save = tf.save(&state.db).await;
        return false;
    }
    if !bool::from(issued.as_bytes().ct_eq(code.trim().as_bytes())) {
        data.attempts = data.attempts.saturating_add(1);
        if data.attempts >= EMAIL_ATTEMPT_LIMIT {
            data.reset_token();
        }
        tf.data = data.to_json();
        let _save = tf.save(&state.db).await;
        return false;
    }
    data.reset_token();
    tf.data = data.to_json();
    let _save = tf.save(&state.db).await;
    true
}

// ---------------------------------------------------------------------------
// Recovery codes. We store a single 20-char hex code on the User row's
// `totp_recover` column. `recover` deletes every TwoFactor row + the recover
// code, restoring single-factor login.

fn random_recovery_code() -> String {
    let mut buf = [0u8; 10];
    let _ = getrandom::getrandom(&mut buf);
    let mut s = String::with_capacity(20);
    for b in buf {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Lazily mint a recovery code on the user row when the first 2FA method is
/// enrolled. Mirrors upstream's `generate_recover_code` no-op when one already
/// exists.
async fn ensure_recovery_code(state: &AppState, user: &mut User) -> Result<(), String> {
    if user.totp_recover.as_deref().is_some_and(|s| !s.is_empty()) {
        return Ok(());
    }
    user.totp_recover = Some(random_recovery_code());
    user.save(&state.db).await.map_err(|e| e.to_string())
}

#[worker::send]
async fn get_recover(
    AxumState(state): AxumState<AppState>,
    headers: Headers,
    Json(body): Json<PasswordOrOtpData>,
) -> impl IntoResponse {
    if let Err(e) = check_password_or_otp(&headers.user, &body) {
        return e;
    }
    let mut user = headers.user.clone();
    if let Err(e) = ensure_recovery_code(&state, &mut user).await {
        state.telemetry.record("recover_code_save_failed", &[("err", &e)]);
        return err_json(StatusCode::INTERNAL_SERVER_ERROR, "failed to generate recovery code");
    }
    (
        StatusCode::OK,
        Json(json!({
            "Object": "twoFactorRecover",
            "Code": user.totp_recover.unwrap_or_default(),
        })),
    )
}

#[derive(Deserialize)]
struct RecoverData {
    #[serde(alias = "MasterPasswordHash")]
    master_password_hash: String,
    #[serde(alias = "Email")]
    email: String,
    #[serde(alias = "RecoveryCode")]
    recovery_code: String,
}

#[worker::send]
async fn recover(
    AxumState(state): AxumState<AppState>,
    Json(body): Json<RecoverData>,
) -> impl IntoResponse {
    let email = body.email.trim().to_lowercase();
    let mut user = match User::find_by_email(&state.db, &email).await {
        Ok(Some(u)) => u,
        _ => return err_json(StatusCode::BAD_REQUEST, "Username or password is incorrect"),
    };
    if !user.check_valid_password(&body.master_password_hash) {
        return err_json(StatusCode::BAD_REQUEST, "Username or password is incorrect");
    }
    let stored = user.totp_recover.clone().unwrap_or_default();
    if stored.is_empty() {
        return err_json(StatusCode::BAD_REQUEST, "Recovery code is not set on this account");
    }
    let supplied = body.recovery_code.trim().to_lowercase().replace(' ', "");
    if !bool::from(stored.as_bytes().ct_eq(supplied.as_bytes())) {
        return err_json(StatusCode::BAD_REQUEST, "Recovery code is invalid");
    }
    let factors = TwoFactor::find_by_user(&state.db, &user.uuid).await.unwrap_or_default();
    for tf in factors {
        let _del = tf.delete(&state.db).await;
    }
    user.totp_recover = None;
    user.security_stamp = uuid::Uuid::new_v4().to_string();
    if user.save(&state.db).await.is_err() {
        return err_json(StatusCode::INTERNAL_SERVER_ERROR, "failed to clear 2FA");
    }
    crate::api::notify::notify_user(
        &state,
        &user.uuid,
        crate::api::notify::kind::LOG_OUT,
        &user.uuid,
    )
    .await;
    crate::api::events::log_user_event(
        &state,
        crate::api::events::event_type::USER_RECOVERED_2FA,
        &user.uuid,
        14,
    )
    .await;
    (StatusCode::OK, Json(Value::Null))
}

/// Mint a per-device 2FA-remember token, persist it on the user's TwoFactor
/// row keyed by device, and return the token for the client to stash. The
/// token is opaque (UUID); next login the client passes it back as the
/// `twoFactorToken` and we accept it without re-prompting.
pub async fn issue_remember_token(state: &AppState, user_uuid: &str, device_uuid: &str) -> String {
    let token = format!("{}:{}", device_uuid, uuid::Uuid::new_v4());
    let mut row = TwoFactor::new(user_uuid.to_owned(), TWOFACTOR_TYPE_REMEMBER, token.clone());
    row.enabled = 1;
    let _save = row.save(&state.db).await;
    token
}

/// Check whether a presented 2FA-remember token is valid for the given user
/// and device. The token format is `{device_uuid}:{uuid}` so we can scope the
/// match to the same device that stashed it.
pub async fn check_remember_token(
    state: &AppState,
    user_uuid: &str,
    device_uuid: &str,
    token: &str,
) -> bool {
    use subtle::ConstantTimeEq;
    let Some(prefix) = token.split_once(':').map(|(d, _)| d) else {
        return false;
    };
    if prefix != device_uuid {
        return false;
    }
    let factors = TwoFactor::find_by_user(&state.db, user_uuid).await.unwrap_or_default();
    factors.iter().any(|f| {
        f.atype == TWOFACTOR_TYPE_REMEMBER
            && bool::from(f.data.as_bytes().ct_eq(token.as_bytes()))
    })
}

#[worker::send]
async fn device_verification_settings(_headers: Headers) -> impl IntoResponse {
    (
        StatusCode::OK,
        Json(json!({
            "Object": "deviceVerificationSettings",
            "IsTwoFactorPolicyEnabled": false,
            "IsDeviceVerificationEnabled": false,
            "UnknownDeviceVerificationEnabled": false,
        })),
    )
}

#[worker::send]
async fn get_duo_stub(
    _state: AxumState<AppState>,
    headers: Headers,
    Json(body): Json<PasswordOrOtpData>,
) -> impl IntoResponse {
    if let Err(e) = check_password_or_otp(&headers.user, &body) {
        return e;
    }
    (
        StatusCode::OK,
        Json(json!({
            "Object": "twoFactorDuo",
            "Enabled": false,
            "Host": "",
            "SecretKey": "",
            "IntegrationKey": "",
        })),
    )
}

#[worker::send]
async fn duo_unsupported(
    _state: AxumState<AppState>,
    _headers: Headers,
    Json(_body): Json<Value>,
) -> impl IntoResponse {
    err_json(StatusCode::NOT_IMPLEMENTED, "Duo 2FA is not yet supported on this Worker")
}

// ---------------------------------------------------------------------------
// YubiKey OTP. We talk to Yubico's HTTP verification API directly. The
// operator must set `YUBICO_CLIENT_ID` + `YUBICO_SECRET_KEY` (and optionally
// `YUBICO_SERVER`) for enrollment + login to work; without them the
// `get-yubikey` and `yubikey` routes return shape-correct disabled responses.

const TWOFACTOR_TYPE_YUBIKEY: i32 = 3;

#[derive(serde::Serialize, Deserialize)]
struct YubikeyMetadata {
    #[serde(rename = "keys", alias = "Keys")]
    keys: Vec<String>,
    #[serde(rename = "nfc", alias = "Nfc", default)]
    nfc: bool,
}

fn yubico_credentials(state: &AppState) -> Option<(String, String)> {
    let id = state.env_var("YUBICO_CLIENT_ID")?;
    let key = state.env_var("YUBICO_SECRET_KEY")?;
    if id.is_empty() || key.is_empty() {
        return None;
    }
    Some((id, key))
}

fn yubico_server(state: &AppState) -> String {
    state
        .env_var("YUBICO_SERVER")
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "https://api.yubico.com/wsapi/2.0/verify".to_owned())
}

#[worker::send]
async fn verify_yubikey_otp(state: &AppState, otp: &str) -> Result<(), String> {
    use base64::Engine as _;
    use hmac::{Hmac, Mac};
    use sha1::Sha1;
    type HmacSha1 = Hmac<Sha1>;

    let (client_id, secret_b64) = yubico_credentials(state).ok_or_else(|| "Yubico not configured".to_owned())?;
    let key = base64::engine::general_purpose::STANDARD
        .decode(secret_b64.as_bytes())
        .map_err(|e| format!("invalid secret: {e}"))?;

    let mut nonce_bytes = [0u8; 20];
    let _ = getrandom::getrandom(&mut nonce_bytes);
    let nonce: String = nonce_bytes.iter().map(|b| format!("{b:02x}")).collect();

    // Yubico signs the params alphabetically with HMAC-SHA1 of `key=value&...`
    // and base64 of the digest.
    let mut pairs = vec![
        ("id", client_id.as_str()),
        ("nonce", nonce.as_str()),
        ("otp", otp),
        ("timestamp", "1"),
    ];
    pairs.sort_by_key(|(k, _)| *k);
    let to_sign = pairs
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&");

    let mut mac = HmacSha1::new_from_slice(&key).map_err(|e| e.to_string())?;
    mac.update(to_sign.as_bytes());
    let signature = base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes());

    let url = format!(
        "{}?{to_sign}&h={}",
        yubico_server(state),
        urlencoding_minimal(&signature),
    );
    let mut init = worker::RequestInit::new();
    init.with_method(worker::Method::Get);
    let req = worker::Request::new_with_init(&url, &init).map_err(|e| e.to_string())?;
    let mut resp = worker::Fetch::Request(req).send().await.map_err(|e| e.to_string())?;
    let body = resp.text().await.map_err(|e| e.to_string())?;
    // Response is `key=value\nkey=value\n` form. We only need `status=OK`.
    let ok = body
        .lines()
        .any(|line| line.trim() == "status=OK");
    if ok {
        Ok(())
    } else {
        Err(format!("yubico response: {body}"))
    }
}

fn urlencoding_minimal(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                String::from_utf8(vec![b]).unwrap_or_default()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

#[derive(Deserialize)]
struct EnableYubikeyData {
    #[serde(default, rename = "key1")]
    key1: Option<String>,
    #[serde(default, rename = "key2")]
    key2: Option<String>,
    #[serde(default, rename = "key3")]
    key3: Option<String>,
    #[serde(default, rename = "key4")]
    key4: Option<String>,
    #[serde(default, rename = "key5")]
    key5: Option<String>,
    #[serde(default)]
    nfc: bool,
    #[serde(default, alias = "masterPasswordHash")]
    master_password_hash: Option<String>,
    #[serde(default)]
    otp: Option<String>,
}

fn extract_yubikeys(d: &EnableYubikeyData) -> Vec<String> {
    [&d.key1, &d.key2, &d.key3, &d.key4, &d.key5]
        .iter()
        .filter_map(|k| k.as_deref())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_owned())
        .collect()
}

fn yubikey_response(meta: &YubikeyMetadata, enabled: bool) -> Value {
    let mut result = Value::Object(serde_json::Map::new());
    for (i, key) in meta.keys.iter().enumerate() {
        result[format!("Key{}", i + 1)] = Value::String(key.clone());
    }
    result["Enabled"] = Value::Bool(enabled);
    result["Nfc"] = Value::Bool(meta.nfc);
    result["Object"] = Value::String("twoFactorU2f".to_owned());
    result
}

#[worker::send]
async fn get_yubikey_stub(
    AxumState(state): AxumState<AppState>,
    headers: Headers,
    Json(body): Json<PasswordOrOtpData>,
) -> impl IntoResponse {
    if let Err(e) = check_password_or_otp(&headers.user, &body) {
        return e;
    }
    if yubico_credentials(&state).is_none() {
        return (
            StatusCode::OK,
            Json(json!({
                "Object": "twoFactorU2f",
                "Enabled": false,
                "Keys": [],
                "Nfc": false,
            })),
        );
    }
    let row = TwoFactor::find_by_user_and_type(&state.db, &headers.user.uuid, TWOFACTOR_TYPE_YUBIKEY)
        .await
        .ok()
        .flatten();
    let meta = match row.as_ref() {
        Some(tf) => serde_json::from_str::<YubikeyMetadata>(&tf.data)
            .unwrap_or(YubikeyMetadata { keys: vec![], nfc: false }),
        None => YubikeyMetadata { keys: vec![], nfc: false },
    };
    (StatusCode::OK, Json(yubikey_response(&meta, row.is_some())))
}

#[worker::send]
async fn yubikey_unsupported(
    AxumState(state): AxumState<AppState>,
    headers: Headers,
    Json(body): Json<EnableYubikeyData>,
) -> impl IntoResponse {
    let pw = PasswordOrOtpData {
        master_password_hash: body.master_password_hash.clone(),
        otp: body.otp.clone(),
    };
    if let Err(e) = check_password_or_otp(&headers.user, &pw) {
        return e;
    }
    if yubico_credentials(&state).is_none() {
        return err_json(
            StatusCode::BAD_REQUEST,
            "Yubico is not configured. Set YUBICO_CLIENT_ID + YUBICO_SECRET_KEY to enable.",
        );
    }
    let yubikeys = extract_yubikeys(&body);
    if yubikeys.is_empty() {
        return (
            StatusCode::OK,
            Json(json!({
                "Object": "twoFactorU2f",
                "Enabled": false,
                "Keys": [],
                "Nfc": body.nfc,
            })),
        );
    }
    // Verify any 44-char OTP against Yubico; 12-char keys are just identifiers
    // (the user can pre-register without verification).
    for yk in &yubikeys {
        if yk.len() == 44
            && let Err(e) = verify_yubikey_otp(&state, yk).await
        {
            return err_json(StatusCode::BAD_REQUEST, &format!("Invalid YubiKey OTP: {e}"));
        }
    }
    let key_ids: Vec<String> = yubikeys
        .into_iter()
        .filter_map(|s| s.get(..12).map(str::to_owned))
        .collect();
    let meta = YubikeyMetadata { keys: key_ids, nfc: body.nfc };
    let mut row = TwoFactor::new(
        headers.user.uuid.clone(),
        TWOFACTOR_TYPE_YUBIKEY,
        serde_json::to_string(&meta).unwrap_or_default(),
    );
    row.enabled = 1;
    if row.save(&state.db).await.is_err() {
        return err_json(StatusCode::INTERNAL_SERVER_ERROR, "save failed");
    }
    let mut user = headers.user.clone();
    let _recover = ensure_recovery_code(&state, &mut user).await;
    crate::api::events::log_user_event(
        &state,
        crate::api::events::event_type::USER_UPDATED_2FA,
        &headers.user.uuid,
        headers.device.atype,
    )
    .await;
    (StatusCode::OK, Json(yubikey_response(&meta, true)))
}
