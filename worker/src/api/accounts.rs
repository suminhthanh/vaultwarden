use axum::{
    Json, Router,
    extract::State as AxumState,
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::AppState;
use crate::auth::Headers;
use crate::db::models::User;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/accounts/register", post(register))
        .route("/api/accounts/profile", get(get_profile).put(put_profile).post(put_profile))
        .route("/api/accounts/verify-password", post(verify_password))
        .route("/api/accounts/password", post(change_password))
        .route("/api/accounts/kdf", post(change_kdf))
        .route("/api/accounts/password-hint", post(password_hint))
        .route("/api/accounts/delete", post(delete_account))
        .route("/api/accounts", axum::routing::delete(delete_account))
        .route("/api/accounts/revision-date", get(revision_date))
        .route("/api/accounts/email-token", post(request_email_change))
        .route("/api/accounts/email", post(change_email))
        .route("/api/accounts/api-key", post(get_or_create_api_key))
        .route("/api/accounts/rotate-api-key", post(rotate_api_key))
        .route("/api/accounts/request-otp", post(request_otp))
        .route("/api/accounts/verify-otp", post(verify_otp))
        .route("/api/accounts/avatar", post(set_avatar).put(set_avatar))
        .route("/api/accounts/set-password", post(set_password))
        .route("/api/accounts/verify-email", post(verify_email))
        .route("/api/accounts/verify-email-token", post(verify_email_token))
        .route("/api/accounts/delete-recover", post(delete_recover))
        .route("/api/accounts/delete-recover-token", post(delete_recover_token))
        .route("/api/users/{user_id}/public-key", get(user_public_key))
}

#[derive(Deserialize)]
struct RegisterData {
    email: String,
    name: Option<String>,
    #[serde(rename = "masterPasswordHash")]
    master_password_hash: String,
    #[serde(rename = "masterPasswordHint")]
    master_password_hint: Option<String>,
    key: String,
    keys: Option<KeyPair>,
    kdf: Option<i32>,
    #[serde(rename = "kdfIterations")]
    kdf_iterations: Option<i32>,
    #[serde(rename = "kdfMemory")]
    kdf_memory: Option<i32>,
    #[serde(rename = "kdfParallelism")]
    kdf_parallelism: Option<i32>,
}

#[derive(Deserialize)]
struct KeyPair {
    #[serde(rename = "publicKey")]
    public_key: String,
    #[serde(rename = "encryptedPrivateKey")]
    encrypted_private_key: String,
}

fn err_json(code: StatusCode, msg: &str) -> (StatusCode, Json<Value>) {
    (code, Json(json!({ "ErrorModel": { "Message": msg }, "Object": "error", "Message": msg })))
}

/// Minimal RFC3986 percent-encoder for query params (only what we need —
/// emails, names, etc). Mirrors `organizations::urlencoded`.
fn urlencode(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                String::from_utf8(vec![b]).unwrap_or_default()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

#[worker::send]
async fn register(
    AxumState(state): AxumState<AppState>,
    headers: axum::http::HeaderMap,
    Json(data): Json<RegisterData>,
) -> impl IntoResponse {
    let ip = headers
        .get("cf-connecting-ip")
        .or_else(|| headers.get("x-forwarded-for"))
        .and_then(|v| v.to_str().ok())
        .map(|s| s.split(',').next().unwrap_or(s).trim().to_owned())
        .unwrap_or_else(|| "unknown".to_owned());
    if !crate::ratelimit::check(&state.ratelimit_kv, &crate::ratelimit::REGISTER_LIMIT, &ip).await {
        return err_json(StatusCode::TOO_MANY_REQUESTS, "Too many signup attempts");
    }
    let email = data.email.trim().to_lowercase();
    if email.is_empty() {
        return err_json(StatusCode::BAD_REQUEST, "email is required");
    }
    if let Ok(Some(_)) = User::find_by_email(&state.db, &email).await {
        return err_json(StatusCode::BAD_REQUEST, "User already exists");
    }
    if data.master_password_hash.is_empty() {
        return err_json(StatusCode::BAD_REQUEST, "masterPasswordHash is required");
    }

    let mut user = User::new(&email, data.name);
    user.akey = data.key;
    user.password_hint = data.master_password_hint;
    user.client_kdf_type = data.kdf.unwrap_or(0);
    user.client_kdf_iter = data.kdf_iterations.unwrap_or(600_000);
    user.client_kdf_memory = data.kdf_memory;
    user.client_kdf_parallelism = data.kdf_parallelism;
    if let Some(kp) = data.keys {
        user.public_key = Some(kp.public_key);
        user.private_key = Some(kp.encrypted_private_key);
    }
    // The Bitwarden client sends `masterPasswordHash` as a base64 string and uses that same
    // base64 string as the `password` form field on /identity/connect/token. We hash the
    // base64 string with PBKDF2-HMAC-SHA256 over the user's salt to match what login presents.
    user.password_iterations = user.client_kdf_iter;
    user.set_password(&data.master_password_hash);

    if user.save(&state.db).await.is_err() {
        return err_json(StatusCode::INTERNAL_SERVER_ERROR, "failed to save user");
    }

    (StatusCode::OK, Json(json!({ "Object": "register", "CaptchaBypassToken": Value::Null })))
}

fn profile_json(u: &User) -> Value {
    profile_json_with(u, false, &[])
}

fn profile_json_with(u: &User, two_factor_enabled: bool, organizations: &[Value]) -> Value {
    json!({
        "Object": "profile",
        "Id": u.uuid,
        "Name": u.name,
        "Email": u.email,
        "EmailVerified": u.verified_at.is_some(),
        "Premium": true,
        "PremiumFromOrganization": false,
        "MasterPasswordHint": u.password_hint,
        "Culture": "en-US",
        "TwoFactorEnabled": two_factor_enabled,
        "Key": u.akey,
        "PrivateKey": u.private_key,
        "SecurityStamp": u.security_stamp,
        "ForcePasswordReset": false,
        "UsesKeyConnector": false,
        "AvatarColor": u.avatar_color,
        "Organizations": organizations,
        "Providers": [],
        "ProviderOrganizations": [],
    })
}

#[worker::send]
async fn get_profile(
    AxumState(state): AxumState<AppState>,
    headers: Headers,
) -> Json<Value> {
    use crate::db::models::{Membership, Organization, TwoFactor};
    let two_factor_enabled = TwoFactor::find_by_user(&state.db, &headers.user.uuid)
        .await
        .map(|fs| fs.iter().any(|f| f.enabled == 1))
        .unwrap_or(false);
    let memberships = Membership::find_by_user(&state.db, &headers.user.uuid).await.unwrap_or_default();
    let mut orgs = Vec::with_capacity(memberships.len());
    for m in &memberships {
        let name = match Organization::find_by_uuid(&state.db, &m.org_uuid).await {
            Ok(Some(o)) => o.name,
            _ => "(unknown)".to_owned(),
        };
        orgs.push(crate::api::organizations::membership_json(m, &name));
    }
    Json(profile_json_with(&headers.user, two_factor_enabled, &orgs))
}

#[derive(Deserialize)]
struct ProfileData {
    name: Option<String>,
    #[serde(rename = "masterPasswordHint")]
    master_password_hint: Option<String>,
}

#[worker::send]
async fn put_profile(
    AxumState(state): AxumState<AppState>,
    headers: Headers,
    Json(body): Json<ProfileData>,
) -> impl IntoResponse {
    let mut user = headers.user;
    if let Some(name) = body.name {
        user.name = name;
    }
    if body.master_password_hint.is_some() {
        user.password_hint = body.master_password_hint;
    }
    if user.save(&state.db).await.is_err() {
        return err_json(StatusCode::INTERNAL_SERVER_ERROR, "failed to save user");
    }
    (StatusCode::OK, Json(profile_json(&user)))
}

// ---------------------------------------------------------------------------
// Verify password / change password / delete account / public-key / hint

#[derive(Deserialize)]
struct PasswordVerifyBody {
    #[serde(default, rename = "masterPasswordHash")]
    master_password_hash: Option<String>,
}

#[worker::send]
async fn verify_password(
    headers: Headers,
    Json(body): Json<PasswordVerifyBody>,
) -> impl IntoResponse {
    let pw = match body.master_password_hash.as_deref() {
        Some(p) if !p.is_empty() => p,
        _ => return err_json(StatusCode::BAD_REQUEST, "masterPasswordHash is required"),
    };
    if !headers.user.check_valid_password(pw) {
        return err_json(StatusCode::UNAUTHORIZED, "Invalid password");
    }
    (StatusCode::OK, Json(json!({})))
}

#[derive(Deserialize)]
struct ChangePasswordBody {
    #[serde(rename = "masterPasswordHash")]
    master_password_hash: String,
    #[serde(rename = "newMasterPasswordHash")]
    new_master_password_hash: String,
    #[serde(default, rename = "masterPasswordHint")]
    master_password_hint: Option<String>,
    /// New encrypted user symmetric key (re-wrapped under the new master key).
    #[serde(rename = "key")]
    key: String,
}

#[worker::send]
async fn change_password(
    AxumState(state): AxumState<AppState>,
    headers: Headers,
    Json(body): Json<ChangePasswordBody>,
) -> impl IntoResponse {
    let mut user = headers.user;
    if !user.check_valid_password(&body.master_password_hash) {
        return err_json(StatusCode::UNAUTHORIZED, "Invalid password");
    }
    user.set_password(&body.new_master_password_hash);
    user.akey = body.key;
    if let Some(hint) = body.master_password_hint {
        user.password_hint = if hint.is_empty() { None } else { Some(hint) };
    }
    // Rotating the security stamp invalidates every existing access_token.
    user.security_stamp = uuid::Uuid::new_v4().to_string();
    if user.save(&state.db).await.is_err() {
        return err_json(StatusCode::INTERNAL_SERVER_ERROR, "failed to save user");
    }
    state.telemetry.record("password_changed", &[("user", &user.uuid)]);
    crate::api::events::log_user_event(
        &state,
        crate::api::events::event_type::USER_UPDATED_PASSWORD,
        &user.uuid,
        headers.device.atype,
    )
    .await;
    crate::api::notify::notify_user(
        &state,
        &user.uuid,
        crate::api::notify::kind::LOG_OUT,
        &user.uuid,
    )
    .await;
    (StatusCode::OK, Json(json!({})))
}

#[worker::send]
async fn delete_account(
    AxumState(state): AxumState<AppState>,
    headers: Headers,
    Json(body): Json<PasswordVerifyBody>,
) -> impl IntoResponse {
    let pw = match body.master_password_hash.as_deref() {
        Some(p) if !p.is_empty() => p,
        _ => return err_json(StatusCode::BAD_REQUEST, "masterPasswordHash is required"),
    };
    let user = headers.user;
    if !user.check_valid_password(pw) {
        return err_json(StatusCode::UNAUTHORIZED, "Invalid password");
    }

    // Best-effort R2 cleanup before the row cascade. We collect attachment
    // and file-send keys first so the row deletes still succeed if R2 is
    // flaky.
    if let Ok(rows) = state
        .db
        .prepare(
            "SELECT a.cipher_uuid AS cipher_uuid, a.id AS attachment_id \
             FROM attachments a JOIN ciphers c ON c.uuid = a.cipher_uuid \
             WHERE c.user_uuid = ?1",
        )
        .bind(&[worker::wasm_bindgen::JsValue::from_str(&user.uuid)])
    {
        #[derive(serde::Deserialize)]
        struct AttRow { cipher_uuid: String, attachment_id: String }
        if let Ok(result) = rows.all().await
            && let Ok(rows) = result.results::<AttRow>()
        {
            for r in rows {
                let key = format!("{}/{}", r.cipher_uuid, r.attachment_id);
                let _r2 = state.attachments.delete(&key).await;
            }
        }
    }
    if let Ok(send_rows) = state
        .db
        .prepare("SELECT uuid FROM sends WHERE user_uuid = ?1 AND atype = 1")
        .bind(&[worker::wasm_bindgen::JsValue::from_str(&user.uuid)])
    {
        #[derive(serde::Deserialize)]
        struct SendRow { uuid: String }
        if let Ok(result) = send_rows.all().await
            && let Ok(rows) = result.results::<SendRow>()
        {
            for r in rows {
                let prefix = format!("{}/", r.uuid);
                if let Ok(list) = state.sends.list().prefix(prefix).execute().await {
                    for obj in list.objects() {
                        let _r2 = state.sends.delete(obj.key()).await;
                    }
                }
            }
        }
    }

    // Cascade: D1 doesn't have ON DELETE CASCADE on every FK so we walk through
    // owned rows by hand. Org-shared ciphers stay (membership is removed).
    let db = state.db.as_ref();
    let cleanup = async {
        let _r1 = db.prepare("DELETE FROM favorites WHERE user_uuid = ?1")
            .bind(&[worker::wasm_bindgen::JsValue::from_str(&user.uuid)])?
            .run().await?;
        let _r2 = db.prepare("DELETE FROM folders_ciphers WHERE folder_uuid IN (SELECT uuid FROM folders WHERE user_uuid = ?1)")
            .bind(&[worker::wasm_bindgen::JsValue::from_str(&user.uuid)])?
            .run().await?;
        let _r3 = db.prepare("DELETE FROM folders WHERE user_uuid = ?1")
            .bind(&[worker::wasm_bindgen::JsValue::from_str(&user.uuid)])?
            .run().await?;
        // Drop attachment rows that hung off the user's personal ciphers. R2
        // cleanup happens out-of-band via the cron job — we accept some lag
        // there rather than blocking deletion on potentially many R2 ops.
        let _r3b = db.prepare("DELETE FROM attachments WHERE cipher_uuid IN (SELECT uuid FROM ciphers WHERE user_uuid = ?1)")
            .bind(&[worker::wasm_bindgen::JsValue::from_str(&user.uuid)])?
            .run().await?;
        let _r3c = db.prepare("DELETE FROM ciphers_collections WHERE cipher_uuid IN (SELECT uuid FROM ciphers WHERE user_uuid = ?1)")
            .bind(&[worker::wasm_bindgen::JsValue::from_str(&user.uuid)])?
            .run().await?;
        let _r4 = db.prepare("DELETE FROM ciphers WHERE user_uuid = ?1")
            .bind(&[worker::wasm_bindgen::JsValue::from_str(&user.uuid)])?
            .run().await?;
        let _r5 = db.prepare("DELETE FROM sends WHERE user_uuid = ?1")
            .bind(&[worker::wasm_bindgen::JsValue::from_str(&user.uuid)])?
            .run().await?;
        let _r5b = db.prepare("DELETE FROM auth_requests WHERE user_uuid = ?1")
            .bind(&[worker::wasm_bindgen::JsValue::from_str(&user.uuid)])?
            .run().await?;
        let _r5c = db.prepare("DELETE FROM emergency_access WHERE grantor_uuid = ?1 OR grantee_uuid = ?1")
            .bind(&[worker::wasm_bindgen::JsValue::from_str(&user.uuid)])?
            .run().await?;
        let _r5d = db.prepare("DELETE FROM event WHERE user_uuid = ?1")
            .bind(&[worker::wasm_bindgen::JsValue::from_str(&user.uuid)])?
            .run().await?;
        let _r5e = db.prepare("DELETE FROM sso_users WHERE user_uuid = ?1")
            .bind(&[worker::wasm_bindgen::JsValue::from_str(&user.uuid)])?
            .run().await?;
        let _r6 = db.prepare("DELETE FROM devices WHERE user_uuid = ?1")
            .bind(&[worker::wasm_bindgen::JsValue::from_str(&user.uuid)])?
            .run().await?;
        let _r6b = db.prepare("DELETE FROM users_collections WHERE user_uuid = ?1")
            .bind(&[worker::wasm_bindgen::JsValue::from_str(&user.uuid)])?
            .run().await?;
        let _r6c = db.prepare("DELETE FROM groups_users WHERE users_organizations_uuid IN (SELECT uuid FROM users_organizations WHERE user_uuid = ?1)")
            .bind(&[worker::wasm_bindgen::JsValue::from_str(&user.uuid)])?
            .run().await?;
        let _r7 = db.prepare("DELETE FROM users_organizations WHERE user_uuid = ?1")
            .bind(&[worker::wasm_bindgen::JsValue::from_str(&user.uuid)])?
            .run().await?;
        let _r8 = db.prepare("DELETE FROM twofactor WHERE user_uuid = ?1")
            .bind(&[worker::wasm_bindgen::JsValue::from_str(&user.uuid)])?
            .run().await?;
        let _r9 = db.prepare("DELETE FROM users WHERE uuid = ?1")
            .bind(&[worker::wasm_bindgen::JsValue::from_str(&user.uuid)])?
            .run().await?;
        Ok::<(), worker::Error>(())
    };
    if cleanup.await.is_err() {
        return err_json(StatusCode::INTERNAL_SERVER_ERROR, "failed to delete account");
    }
    state.telemetry.record("account_deleted", &[("user", &user.uuid)]);
    crate::api::notify::notify_user(
        &state,
        &user.uuid,
        crate::api::notify::kind::LOG_OUT,
        &user.uuid,
    )
    .await;
    (StatusCode::OK, Json(json!({})))
}

#[derive(Deserialize)]
struct PasswordHintBody {
    email: String,
}

#[worker::send]
async fn password_hint(
    AxumState(state): AxumState<AppState>,
    Json(body): Json<PasswordHintBody>,
) -> impl IntoResponse {
    // Always return 200, regardless of whether the user exists or has a hint.
    // Mirrors upstream's anti-enumeration behaviour.
    let email = body.email.trim().to_lowercase();
    if !crate::ratelimit::check(&state.ratelimit_kv, &crate::ratelimit::EMAIL_SEND_LIMIT, &email).await {
        // Same 200 response so attackers can't use rate-limit signal to enumerate.
        return (StatusCode::OK, Json(json!({})));
    }
    if let Ok(Some(user)) = User::find_by_email(&state.db, &email).await
        && let Some(hint) = user.password_hint.as_deref().filter(|s| !s.is_empty())
    {
        let (from_email, from_name) = state.mail_from.as_ref().clone();
        let _result = state
            .mail
            .send(&crate::mail::MailMessage {
                from_email,
                from_name,
                to: email,
                subject: "Your master password hint".into(),
                text: format!("You requested your master password hint:\n\n{hint}\n"),
                html: None,
            })
            .await;
    }
    (StatusCode::OK, Json(json!({})))
}

#[worker::send]
async fn user_public_key(
    AxumState(state): AxumState<AppState>,
    _headers: Headers,
    axum::extract::Path(user_id): axum::extract::Path<String>,
) -> impl IntoResponse {
    match User::find_by_uuid(&state.db, &user_id).await {
        Ok(Some(u)) => (
            StatusCode::OK,
            Json(json!({
                "Object": "userKey",
                "UserId": u.uuid,
                "PublicKey": u.public_key,
            })),
        ),
        Ok(None) => err_json(StatusCode::NOT_FOUND, "User not found"),
        Err(_) => err_json(StatusCode::INTERNAL_SERVER_ERROR, "database error"),
    }
}

#[derive(Deserialize)]
struct ChangeKdfBody {
    #[serde(rename = "masterPasswordHash")]
    master_password_hash: String,
    #[serde(rename = "newMasterPasswordHash")]
    new_master_password_hash: String,
    #[serde(rename = "key")]
    key: String,
    #[serde(default)]
    kdf: Option<i32>,
    #[serde(default, rename = "kdfIterations")]
    kdf_iterations: Option<i32>,
    #[serde(default, rename = "kdfMemory")]
    kdf_memory: Option<i32>,
    #[serde(default, rename = "kdfParallelism")]
    kdf_parallelism: Option<i32>,
}

#[worker::send]
async fn change_kdf(
    AxumState(state): AxumState<AppState>,
    headers: Headers,
    Json(body): Json<ChangeKdfBody>,
) -> impl IntoResponse {
    let mut user = headers.user;
    if !user.check_valid_password(&body.master_password_hash) {
        return err_json(StatusCode::UNAUTHORIZED, "Invalid password");
    }
    if let Some(k) = body.kdf {
        user.client_kdf_type = k;
    }
    if let Some(it) = body.kdf_iterations {
        user.client_kdf_iter = it;
        user.password_iterations = it;
    }
    user.client_kdf_memory = body.kdf_memory;
    user.client_kdf_parallelism = body.kdf_parallelism;
    user.akey = body.key;
    user.set_password(&body.new_master_password_hash);
    user.security_stamp = uuid::Uuid::new_v4().to_string();
    if user.save(&state.db).await.is_err() {
        return err_json(StatusCode::INTERNAL_SERVER_ERROR, "failed to save user");
    }
    state.telemetry.record("kdf_changed", &[("user", &user.uuid)]);
    crate::api::events::log_user_event(
        &state,
        crate::api::events::event_type::USER_UPDATED_PASSWORD,
        &user.uuid,
        headers.device.atype,
    )
    .await;
    crate::api::notify::notify_user(
        &state,
        &user.uuid,
        crate::api::notify::kind::LOG_OUT,
        &user.uuid,
    )
    .await;
    (StatusCode::OK, Json(json!({})))
}

async fn revision_date(headers: Headers) -> Json<Value> {
    let ts = chrono::DateTime::parse_from_rfc3339(&headers.user.updated_at)
        .ok()
        .map(|d| d.timestamp_millis())
        .unwrap_or(0);
    Json(json!(ts))
}

#[derive(Deserialize)]
struct EmailTokenBody {
    #[serde(rename = "newEmail")]
    new_email: String,
    #[serde(rename = "masterPasswordHash")]
    master_password_hash: String,
}

#[worker::send]
async fn request_email_change(
    AxumState(state): AxumState<AppState>,
    headers: Headers,
    Json(body): Json<EmailTokenBody>,
) -> impl IntoResponse {
    let user = headers.user;
    if !user.check_valid_password(&body.master_password_hash) {
        return err_json(StatusCode::UNAUTHORIZED, "Invalid password");
    }
    let new_email = body.new_email.trim().to_lowercase();
    if new_email.is_empty() {
        return err_json(StatusCode::BAD_REQUEST, "newEmail is required");
    }
    if let Ok(Some(_)) = User::find_by_email(&state.db, &new_email).await {
        return err_json(StatusCode::BAD_REQUEST, "Email already in use");
    }
    if !crate::ratelimit::check(&state.ratelimit_kv, &crate::ratelimit::EMAIL_SEND_LIMIT, &new_email).await {
        return err_json(StatusCode::TOO_MANY_REQUESTS, "Too many email requests");
    }
    let mut user = user;
    let token = {
        let mut buf = [0u8; 4];
        let _ = getrandom::getrandom(&mut buf);
        let n = u32::from_be_bytes(buf) % 1_000_000;
        format!("{n:06}")
    };
    user.email_new = Some(new_email.clone());
    user.email_new_token = Some(token.clone());
    if user.save(&state.db).await.is_err() {
        return err_json(StatusCode::INTERNAL_SERVER_ERROR, "save failed");
    }
    let (from_email, from_name) = state.mail_from.as_ref().clone();
    let _send = state
        .mail
        .send(&crate::mail::MailMessage {
            from_email,
            from_name,
            to: new_email,
            subject: "Verify your new Vaultwarden email".into(),
            text: format!("Your verification code is {token}.\n\nIt expires in 1 hour."),
            html: None,
        })
        .await;
    (StatusCode::OK, Json(json!({})))
}

#[derive(Deserialize)]
struct EmailChangeBody {
    #[serde(rename = "newEmail")]
    new_email: String,
    #[serde(rename = "masterPasswordHash")]
    master_password_hash: String,
    #[serde(rename = "newMasterPasswordHash")]
    new_master_password_hash: String,
    key: String,
    token: String,
}

#[worker::send]
async fn change_email(
    AxumState(state): AxumState<AppState>,
    headers: Headers,
    Json(body): Json<EmailChangeBody>,
) -> impl IntoResponse {
    let mut user = headers.user;
    if !user.check_valid_password(&body.master_password_hash) {
        return err_json(StatusCode::UNAUTHORIZED, "Invalid password");
    }
    let new_email = body.new_email.trim().to_lowercase();
    if user.email_new.as_deref() != Some(new_email.as_str()) {
        return err_json(StatusCode::BAD_REQUEST, "Email change not requested");
    }
    if user.email_new_token.as_deref() != Some(body.token.as_str()) {
        return err_json(StatusCode::BAD_REQUEST, "Invalid token");
    }
    if let Ok(Some(_)) = User::find_by_email(&state.db, &new_email).await {
        return err_json(StatusCode::BAD_REQUEST, "Email already in use");
    }
    user.email = new_email;
    user.email_new = None;
    user.email_new_token = None;
    user.akey = body.key;
    user.set_password(&body.new_master_password_hash);
    user.security_stamp = uuid::Uuid::new_v4().to_string();
    if user.save(&state.db).await.is_err() {
        return err_json(StatusCode::INTERNAL_SERVER_ERROR, "save failed");
    }
    state.telemetry.record("email_changed", &[("user", &user.uuid)]);
    crate::api::events::log_user_event(
        &state,
        crate::api::events::event_type::USER_CHANGED_PASSWORD,
        &user.uuid,
        headers.device.atype,
    )
    .await;
    crate::api::notify::notify_user(
        &state,
        &user.uuid,
        crate::api::notify::kind::LOG_OUT,
        &user.uuid,
    )
    .await;
    (StatusCode::OK, Json(json!({})))
}

#[derive(Deserialize)]
struct ApiKeyBody {
    #[serde(default, rename = "masterPasswordHash")]
    master_password_hash: Option<String>,
}

#[worker::send]
async fn get_or_create_api_key(
    AxumState(state): AxumState<AppState>,
    headers: Headers,
    Json(body): Json<ApiKeyBody>,
) -> impl IntoResponse {
    let pw = match body.master_password_hash.as_deref() {
        Some(p) if !p.is_empty() => p,
        _ => return err_json(StatusCode::BAD_REQUEST, "masterPasswordHash is required"),
    };
    let mut user = headers.user;
    if !user.check_valid_password(pw) {
        return err_json(StatusCode::UNAUTHORIZED, "Invalid password");
    }
    if user.api_key.as_deref().is_none_or(str::is_empty) {
        let mut buf = [0u8; 30];
        let _ = getrandom::getrandom(&mut buf);
        user.api_key = Some(base64_url_no_pad(&buf));
        if user.save(&state.db).await.is_err() {
            return err_json(StatusCode::INTERNAL_SERVER_ERROR, "save failed");
        }
    }
    (StatusCode::OK, Json(json!({ "Object": "apiKey", "ApiKey": user.api_key })))
}

#[worker::send]
async fn rotate_api_key(
    AxumState(state): AxumState<AppState>,
    headers: Headers,
    Json(body): Json<ApiKeyBody>,
) -> impl IntoResponse {
    let pw = match body.master_password_hash.as_deref() {
        Some(p) if !p.is_empty() => p,
        _ => return err_json(StatusCode::BAD_REQUEST, "masterPasswordHash is required"),
    };
    let mut user = headers.user;
    if !user.check_valid_password(pw) {
        return err_json(StatusCode::UNAUTHORIZED, "Invalid password");
    }
    let mut buf = [0u8; 30];
    let _ = getrandom::getrandom(&mut buf);
    user.api_key = Some(base64_url_no_pad(&buf));
    if user.save(&state.db).await.is_err() {
        return err_json(StatusCode::INTERNAL_SERVER_ERROR, "save failed");
    }
    (StatusCode::OK, Json(json!({ "Object": "apiKey", "ApiKey": user.api_key })))
}

// ---------------------------------------------------------------------------
// Account self-service: avatar, set-password (post-OIDC), verify-email,
// delete-recover. These are mostly stubs that match upstream's response shape
// so the web client doesn't error out — full implementations are tracked
// separately.

#[derive(Deserialize)]
struct AvatarBody {
    #[serde(default, rename = "avatarColor")]
    avatar_color: Option<String>,
}

#[worker::send]
async fn set_avatar(
    AxumState(state): AxumState<AppState>,
    headers: Headers,
    Json(body): Json<AvatarBody>,
) -> impl IntoResponse {
    let mut user = headers.user;
    user.avatar_color = body.avatar_color;
    if user.save(&state.db).await.is_err() {
        return err_json(StatusCode::INTERNAL_SERVER_ERROR, "save failed");
    }
    (StatusCode::OK, Json(profile_json(&user)))
}

#[derive(Deserialize)]
struct SetPasswordBody {
    #[serde(rename = "masterPasswordHash")]
    master_password_hash: String,
    #[serde(default, rename = "masterPasswordHint")]
    master_password_hint: Option<String>,
    #[serde(rename = "key", alias = "userSymmetricKey")]
    key: String,
    #[serde(default)]
    keys: Option<SetPasswordKeyPair>,
    #[serde(default)]
    kdf: Option<i32>,
    #[serde(default, rename = "kdfIterations")]
    kdf_iterations: Option<i32>,
    #[serde(default, rename = "kdfMemory")]
    kdf_memory: Option<i32>,
    #[serde(default, rename = "kdfParallelism")]
    kdf_parallelism: Option<i32>,
}

#[derive(Deserialize)]
struct SetPasswordKeyPair {
    #[serde(rename = "publicKey")]
    public_key: String,
    #[serde(rename = "encryptedPrivateKey")]
    encrypted_private_key: String,
}

/// Used by SSO/OIDC login when the account has no master password yet. We
/// accept the supplied hash + key bundle and persist them.
#[worker::send]
async fn set_password(
    AxumState(state): AxumState<AppState>,
    headers: Headers,
    Json(body): Json<SetPasswordBody>,
) -> impl IntoResponse {
    let mut user = headers.user;
    if !user.password_hash.is_empty() {
        return err_json(StatusCode::BAD_REQUEST, "Master password is already set on this account");
    }
    user.akey = body.key;
    user.password_hint = body.master_password_hint;
    if let Some(k) = body.kdf {
        user.client_kdf_type = k;
    }
    if let Some(i) = body.kdf_iterations {
        user.client_kdf_iter = i;
    }
    user.client_kdf_memory = body.kdf_memory;
    user.client_kdf_parallelism = body.kdf_parallelism;
    if let Some(kp) = body.keys {
        user.public_key = Some(kp.public_key);
        user.private_key = Some(kp.encrypted_private_key);
    }
    user.password_iterations = user.client_kdf_iter;
    user.set_password(&body.master_password_hash);
    if user.save(&state.db).await.is_err() {
        return err_json(StatusCode::INTERNAL_SERVER_ERROR, "save failed");
    }
    crate::api::events::log_user_event(
        &state,
        crate::api::events::event_type::USER_CHANGED_PASSWORD,
        &user.uuid,
        headers.device.atype,
    )
    .await;
    (StatusCode::OK, Json(Value::Null))
}

#[worker::send]
async fn verify_email(
    AxumState(state): AxumState<AppState>,
    headers: Headers,
) -> impl IntoResponse {
    // Without SMTP nothing actionable; report success so the client moves on.
    if matches!(state.mail.as_ref(), crate::mail::Provider::Log(_)) {
        return (StatusCode::OK, Json(Value::Null));
    }
    let claims = crate::auth::VerifyEmailClaims::new(&state.keys, headers.user.uuid.clone());
    let token = match state.keys.encode(&claims) {
        Ok(t) => t,
        Err(_) => return err_json(StatusCode::INTERNAL_SERVER_ERROR, "jwt encode failed"),
    };
    let (from_email, from_name) = state.mail_from.as_ref().clone();
    let host = state.env_var("DOMAIN").unwrap_or_default();
    // Bitwarden's verify_email template stitches the URL itself:
    //   {{url}}/#/verify-email/?userId={{user_id}}&token={{token}}
    // so `url` must be the bare host, not a pre-built link.
    let link = format!("{host}/#/verify-email/?userId={}&token={token}", headers.user.uuid);
    let ctx = serde_json::json!({
        "url": host,
        "user_id": headers.user.uuid,
        "token": token,
        "user_name": headers.user.name,
        "user_email": headers.user.email,
    });
    let (subject, text) = crate::templates::render_subject_body("email/verify_email", &ctx)
        .unwrap_or_else(|_| (
            "Verify your Vaultwarden email".into(),
            format!("Click the link below to verify your email.\n\n{link}"),
        ));
    let html = crate::templates::render_subject_body("email/verify_email.html", &ctx)
        .ok()
        .map(|(_, body)| body);
    let _send = state
        .mail
        .send(&crate::mail::MailMessage {
            from_email,
            from_name,
            to: headers.user.email.clone(),
            subject,
            text,
            html,
        })
        .await;
    (StatusCode::OK, Json(Value::Null))
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct VerifyEmailTokenBody {
    #[serde(rename = "userId", alias = "user_id")]
    user_id: String,
    token: String,
}

/// Mark the user's email verified. Token validation is intentionally lenient
/// for now — the verify_email link points to the SPA, which calls back with
/// the same userId/token pair. Hardening to a signed JWT is tracked separately.
#[worker::send]
async fn verify_email_token(
    AxumState(state): AxumState<AppState>,
    Json(body): Json<VerifyEmailTokenBody>,
) -> impl IntoResponse {
    // Verify the JWT — issuer match + exp/nbf within bounds + sub == userId.
    let issuer = crate::auth::VerifyEmailClaims::issuer(&state.keys);
    let claims: crate::auth::VerifyEmailClaims = match state.keys.decode(&body.token, &issuer) {
        Ok(c) => c,
        Err(_) => return err_json(StatusCode::BAD_REQUEST, "Invalid or expired token"),
    };
    if claims.sub != body.user_id {
        return err_json(StatusCode::BAD_REQUEST, "Token does not match user");
    }
    let mut user = match User::find_by_uuid(&state.db, &body.user_id).await {
        Ok(Some(u)) => u,
        _ => return err_json(StatusCode::BAD_REQUEST, "User not found"),
    };
    user.verified_at = Some(chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Micros, true));
    if user.save(&state.db).await.is_err() {
        return err_json(StatusCode::INTERNAL_SERVER_ERROR, "save failed");
    }
    (StatusCode::OK, Json(Value::Null))
}

#[derive(Deserialize)]
struct DeleteRecoverBody {
    email: String,
}

#[worker::send]
async fn delete_recover(
    AxumState(state): AxumState<AppState>,
    Json(body): Json<DeleteRecoverBody>,
) -> impl IntoResponse {
    // Don't reveal account existence — always 200 with the same shape.
    let email = body.email.trim().to_lowercase();
    if email.is_empty() {
        return (StatusCode::OK, Json(Value::Null));
    }
    // Anti-enumeration via timing: ratelimit on the supplied email regardless
    // of whether the account exists, so an attacker can't probe.
    if !crate::ratelimit::check(
        &state.ratelimit_kv,
        &crate::ratelimit::EMAIL_SEND_LIMIT,
        &email,
    )
    .await
    {
        return (StatusCode::OK, Json(Value::Null));
    }
    if let Ok(Some(user)) = User::find_by_email(&state.db, &email).await
        && !matches!(state.mail.as_ref(), crate::mail::Provider::Log(_))
    {
        let claims = crate::auth::DeleteRecoverClaims::new(&state.keys, user.uuid.clone());
        let Ok(token) = state.keys.encode(&claims) else {
            return (StatusCode::OK, Json(Value::Null));
        };
        let (from_email, from_name) = state.mail_from.as_ref().clone();
        let host = state.env_var("DOMAIN").unwrap_or_default();
        let link = format!(
            "{host}/#/verify-recover-delete?userId={}&token={token}&email={}",
            user.uuid,
            urlencode(&user.email),
        );
        let _send = state
            .mail
            .send(&crate::mail::MailMessage {
                from_email,
                from_name,
                to: user.email.clone(),
                subject: "Recover your Vaultwarden account deletion".into(),
                text: format!(
                    "Click the link below to confirm account deletion. If you did not request this, ignore this email.\n\n{link}",
                ),
                html: None,
            })
            .await;
    }
    (StatusCode::OK, Json(Value::Null))
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct DeleteRecoverTokenBody {
    #[serde(rename = "userId", alias = "user_id")]
    user_id: String,
    token: String,
}

#[worker::send]
async fn delete_recover_token(
    AxumState(state): AxumState<AppState>,
    Json(body): Json<DeleteRecoverTokenBody>,
) -> impl IntoResponse {
    let issuer = crate::auth::DeleteRecoverClaims::issuer(&state.keys);
    let claims: crate::auth::DeleteRecoverClaims = match state.keys.decode(&body.token, &issuer) {
        Ok(c) => c,
        Err(_) => return err_json(StatusCode::BAD_REQUEST, "Invalid or expired token"),
    };
    if claims.sub != body.user_id {
        return err_json(StatusCode::BAD_REQUEST, "Token does not match user");
    }
    let user = match User::find_by_uuid(&state.db, &body.user_id).await {
        Ok(Some(u)) => u,
        _ => return err_json(StatusCode::BAD_REQUEST, "User not found"),
    };
    // Best-effort R2 cleanup: drop personal cipher attachments + file sends
    // before the user row goes. Mirrors delete_account.
    if let Ok(rows) = state
        .db
        .prepare(
            "SELECT a.cipher_uuid AS cipher_uuid, a.id AS attachment_id \
             FROM attachments a JOIN ciphers c ON c.uuid = a.cipher_uuid \
             WHERE c.user_uuid = ?1",
        )
        .bind(&[worker::wasm_bindgen::JsValue::from_str(&user.uuid)])
    {
        #[derive(serde::Deserialize)]
        struct R { cipher_uuid: String, attachment_id: String }
        if let Ok(result) = rows.all().await
            && let Ok(rows) = result.results::<R>()
        {
            for r in rows {
                let key = format!("{}/{}", r.cipher_uuid, r.attachment_id);
                let _r2 = state.attachments.delete(&key).await;
            }
        }
    }
    if let Ok(send_rows) = state
        .db
        .prepare("SELECT uuid FROM sends WHERE user_uuid = ?1 AND atype = 1")
        .bind(&[worker::wasm_bindgen::JsValue::from_str(&user.uuid)])
    {
        #[derive(serde::Deserialize)]
        struct R { uuid: String }
        if let Ok(result) = send_rows.all().await
            && let Ok(rows) = result.results::<R>()
        {
            for r in rows {
                let prefix = format!("{}/", r.uuid);
                if let Ok(list) = state.sends.list().prefix(prefix).execute().await {
                    for obj in list.objects() {
                        let _r2 = state.sends.delete(obj.key()).await;
                    }
                }
            }
        }
    }
    let deleted_uuid = user.uuid.clone();
    if user.delete(&state.db).await.is_err() {
        return err_json(StatusCode::INTERNAL_SERVER_ERROR, "delete failed");
    }
    crate::api::notify::notify_user(
        &state,
        &deleted_uuid,
        crate::api::notify::kind::LOG_OUT,
        &deleted_uuid,
    )
    .await;
    (StatusCode::OK, Json(Value::Null))
}

fn base64_url_no_pad(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

// ---------------------------------------------------------------------------
// Protected actions (request-otp / verify-otp).
//
// Used to gate the vault export and a few other "elevated" actions: the user
// is emailed a 6-digit code and must echo it back. Stored on the same
// `twofactor` table as a row with atype = 4 (ProtectedActions). The token TTL
// matches upstream's email_expiration_time (10 min) and we cap attempts at 3.

const TWOFACTOR_TYPE_PROTECTED_ACTIONS: i32 = 4;
const PROTECTED_OTP_TTL_SECS: i64 = 600;
const PROTECTED_OTP_MAX_ATTEMPTS: u32 = 3;

#[derive(serde::Serialize, Deserialize)]
struct ProtectedOtpData {
    token: String,
    token_sent: i64,
    attempts: u32,
}

fn now_ts() -> i64 {
    (worker::Date::now().as_millis() / 1000) as i64
}

fn random_otp() -> String {
    let mut buf = [0u8; 4];
    let _ = getrandom::getrandom(&mut buf);
    let n = u32::from_be_bytes(buf) % 1_000_000;
    format!("{n:06}")
}

#[worker::send]
async fn request_otp(
    AxumState(state): AxumState<AppState>,
    headers: Headers,
) -> impl IntoResponse {
    if matches!(state.mail.as_ref(), crate::mail::Provider::Log(_)) {
        return err_json(
            StatusCode::BAD_REQUEST,
            "Email is disabled for this server. Configure SMTP/Resend/MailChannels to use protected actions.",
        );
    }
    if !crate::ratelimit::check(&state.ratelimit_kv, &crate::ratelimit::EMAIL_SEND_LIMIT, &headers.user.uuid).await {
        return err_json(StatusCode::TOO_MANY_REQUESTS, "Too many email requests");
    }
    if let Ok(Some(prev)) = crate::db::models::TwoFactor::find_by_user_and_type(
        &state.db,
        &headers.user.uuid,
        TWOFACTOR_TYPE_PROTECTED_ACTIONS,
    )
    .await
        && let Ok(parsed) = serde_json::from_str::<ProtectedOtpData>(&prev.data)
    {
        let elapsed = now_ts() - parsed.token_sent;
        if elapsed < 30 {
            return err_json(
                StatusCode::TOO_MANY_REQUESTS,
                &format!("Please wait {} seconds before requesting another code.", 30 - elapsed),
            );
        }
        if prev.delete(&state.db).await.is_err() {
            return err_json(StatusCode::INTERNAL_SERVER_ERROR, "failed to clear stale OTP");
        }
    }

    let token = random_otp();
    let payload = ProtectedOtpData { token: token.clone(), token_sent: now_ts(), attempts: 0 };
    let row = crate::db::models::TwoFactor::new(
        headers.user.uuid.clone(),
        TWOFACTOR_TYPE_PROTECTED_ACTIONS,
        serde_json::to_string(&payload).unwrap_or_default(),
    );
    if row.save(&state.db).await.is_err() {
        return err_json(StatusCode::INTERNAL_SERVER_ERROR, "failed to save OTP");
    }

    let (from_email, from_name) = state.mail_from.as_ref().clone();
    let text = format!(
        "Your Vaultwarden verification code is {token}.\n\nIt expires in 10 minutes. If you did not request this, ignore this email.",
    );
    if let Err(e) = state
        .mail
        .send(&crate::mail::MailMessage {
            from_email,
            from_name,
            to: headers.user.email.clone(),
            subject: "Your Vaultwarden verification code".into(),
            text,
            html: None,
        })
        .await
    {
        state.telemetry.record("protected_otp_send_failed", &[("err", &e.to_string())]);
        return err_json(StatusCode::INTERNAL_SERVER_ERROR, "failed to send verification email");
    }
    (StatusCode::OK, Json(Value::Null))
}

#[derive(Deserialize)]
struct VerifyOtpData {
    #[serde(rename = "OTP", alias = "otp")]
    otp: String,
}

#[worker::send]
async fn verify_otp(
    AxumState(state): AxumState<AppState>,
    headers: Headers,
    Json(body): Json<VerifyOtpData>,
) -> impl IntoResponse {
    let mut row = match crate::db::models::TwoFactor::find_by_user_and_type(
        &state.db,
        &headers.user.uuid,
        TWOFACTOR_TYPE_PROTECTED_ACTIONS,
    )
    .await
    {
        Ok(Some(r)) => r,
        _ => return err_json(StatusCode::BAD_REQUEST, "Protected action token not found"),
    };
    let mut data: ProtectedOtpData = match serde_json::from_str(&row.data) {
        Ok(d) => d,
        Err(_) => return err_json(StatusCode::BAD_REQUEST, "OTP data corrupt"),
    };
    data.attempts = data.attempts.saturating_add(1);
    row.data = serde_json::to_string(&data).unwrap_or_default();

    if data.attempts > PROTECTED_OTP_MAX_ATTEMPTS {
        let _del = row.delete(&state.db).await;
        return err_json(StatusCode::BAD_REQUEST, "Token has expired");
    }
    if now_ts() - data.token_sent > PROTECTED_OTP_TTL_SECS {
        let _del = row.delete(&state.db).await;
        return err_json(StatusCode::BAD_REQUEST, "Token has expired");
    }
    let supplied = body.otp.trim();
    use subtle::ConstantTimeEq;
    if !bool::from(data.token.as_bytes().ct_eq(supplied.as_bytes())) {
        let _save = row.save(&state.db).await;
        return err_json(StatusCode::BAD_REQUEST, "Token is invalid");
    }
    // Success: consume the token.
    if row.delete(&state.db).await.is_err() {
        return err_json(StatusCode::INTERNAL_SERVER_ERROR, "failed to consume OTP");
    }
    (StatusCode::OK, Json(Value::Null))
}
