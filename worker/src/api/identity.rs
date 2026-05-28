use axum::{
    Json, Router,
    extract::{Form, State as AxumState},
    http::StatusCode,
    response::IntoResponse,
    routing::post,
};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::auth::{LoginJwtClaims, RegisterVerifyClaims};
use crate::db::models::{Device, User};
use crate::AppState;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/identity/connect/token", post(connect_token))
        .route(
            "/identity/accounts/register/send-verification-email",
            post(register_send_verification_email),
        )
        .route("/identity/accounts/register/finish", post(register_finish))
        .route("/identity/accounts/prelogin", post(prelogin))
        .route("/identity/accounts/prelogin/password", post(prelogin))
}

#[derive(Deserialize)]
struct ConnectData {
    grant_type: String,
    username: Option<String>,
    password: Option<String>,
    scope: Option<String>,
    client_id: Option<String>,
    refresh_token: Option<String>,
    #[serde(rename = "deviceIdentifier")]
    device_identifier: Option<String>,
    #[serde(rename = "deviceName")]
    device_name: Option<String>,
    #[serde(rename = "deviceType")]
    device_type: Option<String>,
    #[serde(default, rename = "twoFactorToken", alias = "two_factor_token")]
    two_factor_token: Option<String>,
    #[serde(default, rename = "twoFactorProvider", alias = "two_factor_provider")]
    two_factor_provider: Option<i32>,
    #[serde(default, rename = "twoFactorRemember", alias = "two_factor_remember")]
    two_factor_remember: Option<i32>,
    // Passwordless login fields. The client posts the auth_request UUID it
    // got at request creation time + the random access code it generated;
    // we mint a token if the request has been approved.
    #[serde(default, rename = "authRequest", alias = "auth_request")]
    auth_request: Option<String>,
    #[serde(default, rename = "authRequestAccessCode", alias = "auth_request_access_code")]
    auth_request_access_code: Option<String>,
    // client_credentials grant: client_id is the user/org id with `user.`
    // or `organization.` prefix, client_secret is the API key. Used by the
    // CLI (`bw login --apikey`) and SCIM tools.
    #[serde(default)]
    client_secret: Option<String>,
}

fn error_response(code: StatusCode, error: &str, description: &str) -> (StatusCode, Json<Value>) {
    (
        code,
        Json(json!({
            "error": error,
            "error_description": description,
            "ErrorModel": { "Message": description },
        })),
    )
}

#[worker::send]
async fn connect_token(
    AxumState(state): AxumState<AppState>,
    headers: axum::http::HeaderMap,
    Form(data): Form<ConnectData>,
) -> impl IntoResponse {
    let ip = client_ip(&headers);
    if !crate::ratelimit::check(&state.ratelimit_kv, &crate::ratelimit::LOGIN_LIMIT, &ip).await {
        return error_response(StatusCode::TOO_MANY_REQUESTS, "rate_limited", "Too many login attempts");
    }
    match data.grant_type.as_str() {
        "password" => password_grant(state, data).await,
        "refresh_token" => refresh_grant(state, data).await,
        "authorization_code" | "auth_request" => auth_request_grant(state, data).await,
        "client_credentials" => api_key_grant(state, data).await,
        _ => error_response(
            StatusCode::BAD_REQUEST,
            "unsupported_grant_type",
            "Only password, refresh_token, auth_request, and client_credentials grant types are supported.",
        ),
    }
}

#[derive(Deserialize)]
struct PreloginBody {
    email: String,
}

#[worker::send]
async fn prelogin(
    AxumState(state): AxumState<AppState>,
    Json(body): Json<PreloginBody>,
) -> Json<Value> {
    let email = body.email.trim().to_lowercase();
    let (kdf_type, kdf_iter, kdf_mem, kdf_para) = match User::find_by_email(&state.db, &email).await {
        Ok(Some(u)) => (
            u.client_kdf_type,
            u.client_kdf_iter,
            u.client_kdf_memory,
            u.client_kdf_parallelism,
        ),
        // Unknown email — return defaults so we don't reveal account existence.
        _ => (0, 600_000, None, None),
    };
    Json(json!({
        "kdf": kdf_type,
        "kdfIterations": kdf_iter,
        "kdfMemory": kdf_mem,
        "kdfParallelism": kdf_para,
    }))
}

fn client_ip(headers: &axum::http::HeaderMap) -> String {
    headers
        .get("cf-connecting-ip")
        .or_else(|| headers.get("x-forwarded-for"))
        .and_then(|v| v.to_str().ok())
        .map(|s| s.split(',').next().unwrap_or(s).trim().to_owned())
        .unwrap_or_else(|| "unknown".to_owned())
}

#[derive(Deserialize)]
struct RegisterVerificationData {
    email: String,
    #[serde(default)]
    name: Option<String>,
    #[serde(default, rename = "receiveMarketingEmails")]
    _receive_marketing_emails: Option<bool>,
}

#[worker::send]
async fn register_send_verification_email(
    AxumState(state): AxumState<AppState>,
    headers: axum::http::HeaderMap,
    Json(body): Json<RegisterVerificationData>,
) -> impl IntoResponse {
    let ip = client_ip(&headers);
    if !crate::ratelimit::check(&state.ratelimit_kv, &crate::ratelimit::REGISTER_LIMIT, &ip).await {
        return error_response(StatusCode::TOO_MANY_REQUESTS, "rate_limited", "Too many signup attempts");
    }

    let email = body.email.trim().to_lowercase();
    if email.is_empty() {
        return error_response(StatusCode::BAD_REQUEST, "invalid_request", "email is required");
    }

    // Whether SMTP is configured determines if we email the token or hand it
    // to the client directly. We treat a `LogProvider` (the dev default) as
    // "no real email" — match upstream's `mail_enabled() && signups_verify()`
    // by emailing only when a real provider is wired.
    let mail_enabled = !matches!(state.mail.as_ref(), crate::mail::Provider::Log(_));

    let claims = RegisterVerifyClaims::new(&state.keys, email.clone(), body.name.clone(), mail_enabled);
    let token = match state.keys.encode(&claims) {
        Ok(t) => t,
        Err(_) => return error_response(StatusCode::INTERNAL_SERVER_ERROR, "server_error", "jwt encode failed"),
    };

    if mail_enabled {
        let (from_email, from_name) = state.mail_from.as_ref().clone();
        let domain = state.env_var("DOMAIN").unwrap_or_default();
        let link = format!("{domain}/#/finish-signup?token={token}&email={email}");
        let text = format!(
            "Verify your email address to finish creating your Vaultwarden account.\n\n{link}\n\nIf you did not request this, ignore this email.",
        );
        if let Err(e) = state
            .mail
            .send(&crate::mail::MailMessage {
                from_email,
                from_name,
                to: email.clone(),
                subject: "Verify your Vaultwarden email".into(),
                text,
                html: None,
            })
            .await
        {
            state.telemetry.record(
                "register_send_verification_mail_failed",
                &[("email", &email), ("err", &e.to_string())],
            );
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "Failed to send verification email",
            );
        }

        state.telemetry.record("register_send_verification", &[("email", &email), ("mail", "sent")]);
        // Bitwarden web client expects 200 with an empty JSON body when mail
        // verification is in flight (rather than 204 — Workers reject bodies
        // on 204).
        return (StatusCode::OK, Json(Value::Null));
    }

    // No SMTP — return the token directly so the client can call /finish.
    state.telemetry.record("register_send_verification", &[("email", &email), ("mail", "disabled")]);
    (StatusCode::OK, Json(Value::String(token)))
}

#[derive(Deserialize)]
struct RegisterFinishData {
    email: String,
    #[serde(default)]
    name: Option<String>,
    #[serde(default, rename = "emailVerificationToken")]
    email_verification_token: Option<String>,
    #[serde(rename = "masterPasswordHash")]
    master_password_hash: String,
    #[serde(default, rename = "masterPasswordHint")]
    master_password_hint: Option<String>,
    #[serde(rename = "userSymmetricKey", alias = "key")]
    user_symmetric_key: String,
    #[serde(rename = "userAsymmetricKeys", alias = "keys")]
    user_asymmetric_keys: Option<KeyPair>,
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
struct KeyPair {
    #[serde(rename = "publicKey")]
    public_key: String,
    #[serde(rename = "encryptedPrivateKey")]
    encrypted_private_key: String,
}

#[worker::send]
async fn register_finish(
    AxumState(state): AxumState<AppState>,
    Json(body): Json<RegisterFinishData>,
) -> impl IntoResponse {
    let email = body.email.trim().to_lowercase();
    if email.is_empty() {
        return error_response(StatusCode::BAD_REQUEST, "invalid_request", "email is required");
    }

    // If a verification token was issued, validate it. Issued tokens carry
    // the email in `sub`; mismatch or expiry → reject. When SMTP is disabled
    // upstream still issues a token but flags `verified=false`; we treat both
    // states as acceptable here for the no-mail path.
    if let Some(tok) = body.email_verification_token.as_deref().filter(|s| !s.is_empty()) {
        let issuer = RegisterVerifyClaims::issuer(&state.keys);
        let claims: RegisterVerifyClaims = match state.keys.decode(tok, &issuer) {
            Ok(c) => c,
            Err(_) => {
                return error_response(
                    StatusCode::BAD_REQUEST,
                    "invalid_grant",
                    "Invalid or expired verification token",
                );
            }
        };
        if claims.sub.to_lowercase() != email {
            return error_response(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "Token email does not match",
            );
        }
    }

    if let Ok(Some(_)) = User::find_by_email(&state.db, &email).await {
        return error_response(StatusCode::BAD_REQUEST, "invalid_grant", "User already exists");
    }
    if body.master_password_hash.is_empty() {
        return error_response(StatusCode::BAD_REQUEST, "invalid_request", "masterPasswordHash is required");
    }

    let mut user = User::new(&email, body.name);
    user.akey = body.user_symmetric_key;
    user.password_hint = body.master_password_hint;
    user.client_kdf_type = body.kdf.unwrap_or(0);
    user.client_kdf_iter = body.kdf_iterations.unwrap_or(600_000);
    user.client_kdf_memory = body.kdf_memory;
    user.client_kdf_parallelism = body.kdf_parallelism;
    if let Some(kp) = body.user_asymmetric_keys {
        user.public_key = Some(kp.public_key);
        user.private_key = Some(kp.encrypted_private_key);
    }
    user.password_iterations = user.client_kdf_iter;
    user.set_password(&body.master_password_hash);

    if user.save(&state.db).await.is_err() {
        return error_response(StatusCode::INTERNAL_SERVER_ERROR, "server_error", "failed to save user");
    }

    // Best-effort welcome email rendered via the upstream Handlebars
    // template. Falls back to a plain-text greeting if the template fails to
    // compile (shouldn't happen post-init).
    let (from_email, from_name) = state.mail_from.as_ref().clone();
    let host = state.env_var("DOMAIN").unwrap_or_default();
    let ctx = serde_json::json!({
        "url": host,
        "user_name": user.name,
        "user_email": user.email,
    });
    let (subject, text) = crate::templates::render_subject_body("email/welcome", &ctx)
        .unwrap_or_else(|_| (
            "Welcome to Vaultwarden".into(),
            format!("Welcome to Vaultwarden, {}!", user.name),
        ));
    let html = crate::templates::render_subject_body("email/welcome.html", &ctx)
        .ok()
        .map(|(_, body)| body);
    let _send = state
        .mail
        .send(&crate::mail::MailMessage {
            from_email,
            from_name,
            to: email.clone(),
            subject,
            text,
            html,
        })
        .await;

    state.telemetry.record("register_finish", &[("email", &email)]);
    (StatusCode::OK, Json(json!({ "Object": "register", "CaptchaBypassToken": Value::Null })))
}

fn two_factor_required_response(providers: &[i32]) -> (StatusCode, Json<Value>) {
    let mut providers2 = serde_json::Map::new();
    for p in providers {
        providers2.insert(p.to_string(), Value::Null);
    }
    (
        StatusCode::BAD_REQUEST,
        Json(json!({
            "error": "invalid_grant",
            "error_description": "Two factor required.",
            "TwoFactorProviders": providers.iter().map(|p| p.to_string()).collect::<Vec<_>>(),
            "TwoFactorProviders2": providers2,
            "MasterPasswordPolicy": { "Object": "masterPasswordPolicy" },
            "ErrorModel": { "Message": "Two-factor code required" },
        })),
    )
}

/// Passwordless login final step. The auth_request UUID + access code prove
/// possession of the request, and the request must already be approved by an
/// already-authenticated device. We mint the same login response shape as a
/// password grant so the client can finish unlocking.
async fn auth_request_grant(state: AppState, data: ConnectData) -> (StatusCode, Json<Value>) {
    use crate::db::models::{AuthRequest, Device};
    use subtle::ConstantTimeEq;

    let Some(req_id) = data.auth_request.as_deref().filter(|s| !s.is_empty()) else {
        return error_response(StatusCode::BAD_REQUEST, "invalid_request", "authRequest is required");
    };
    let Some(code) = data.auth_request_access_code.as_deref().filter(|s| !s.is_empty()) else {
        return error_response(StatusCode::BAD_REQUEST, "invalid_request", "authRequestAccessCode is required");
    };

    let r = match AuthRequest::find_by_uuid(&state.db, req_id).await {
        Ok(Some(r)) => r,
        Ok(None) => return error_response(StatusCode::BAD_REQUEST, "invalid_grant", "Auth request not found"),
        Err(_) => return error_response(StatusCode::INTERNAL_SERVER_ERROR, "server_error", "database error"),
    };
    if !bool::from(r.access_code.as_bytes().ct_eq(code.as_bytes())) {
        return error_response(StatusCode::BAD_REQUEST, "invalid_grant", "Access code mismatch");
    }
    if r.approved != Some(1) {
        return error_response(StatusCode::BAD_REQUEST, "invalid_grant", "Auth request not approved");
    }
    // Auth requests are valid for ~5 minutes; reject anything older.
    if let Ok(created) = chrono::DateTime::parse_from_rfc3339(&r.creation_date)
        && (chrono::Utc::now() - created.with_timezone(&chrono::Utc)) > chrono::Duration::minutes(15)
    {
        return error_response(StatusCode::BAD_REQUEST, "invalid_grant", "Auth request expired");
    }

    let user = match User::find_by_uuid(&state.db, &r.user_uuid).await {
        Ok(Some(u)) => u,
        Ok(None) => return error_response(StatusCode::BAD_REQUEST, "invalid_grant", "User no longer exists"),
        Err(_) => return error_response(StatusCode::INTERNAL_SERVER_ERROR, "server_error", "database error"),
    };
    if user.enabled == 0 {
        return error_response(StatusCode::BAD_REQUEST, "invalid_grant", "User disabled");
    }

    let device_identifier = data.device_identifier.unwrap_or_else(|| r.request_device_identifier.clone());
    let device_name = data.device_name.unwrap_or_else(|| "passwordless".into());
    let device_atype: i32 = data.device_type.as_deref().and_then(|s| s.parse().ok()).unwrap_or(r.device_type);

    let mut device = match Device::find(&state.db, &device_identifier, &user.uuid).await {
        Ok(Some(d)) => d,
        Ok(None) => {
            let mut d = Device::new(user.uuid.clone(), device_name, device_atype);
            d.uuid = device_identifier;
            d
        }
        Err(_) => {
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "server_error", "database error");
        }
    };
    device.refresh_token = uuid::Uuid::new_v4().to_string();
    if device.save(&state.db).await.is_err() {
        return error_response(StatusCode::INTERNAL_SERVER_ERROR, "server_error", "database error");
    }

    let scope_str = data.scope.as_deref().unwrap_or("api offline_access");
    let scope_vec: Vec<String> = scope_str.split_whitespace().map(str::to_owned).collect();
    let claims = LoginJwtClaims::new_for(&state.keys, &device, &user, scope_vec, data.client_id);
    let access_token = match state.keys.encode(&claims) {
        Ok(t) => t,
        Err(_) => return error_response(StatusCode::INTERNAL_SERVER_ERROR, "server_error", "jwt encode failed"),
    };

    state.telemetry.record("login_passwordless", &[("user", &user.uuid)]);
    crate::api::events::log_user_event(
        &state,
        crate::api::events::event_type::USER_LOGGED_IN,
        &user.uuid,
        device_atype,
    )
    .await;

    (
        StatusCode::OK,
        Json(json!({
            "access_token": access_token,
            "expires_in": claims.expires_in(),
            "token_type": "Bearer",
            "refresh_token": device.refresh_token,
            "Key": user.akey,
            "PrivateKey": user.private_key,
            "Kdf": user.client_kdf_type,
            "KdfIterations": user.client_kdf_iter,
            "KdfMemory": user.client_kdf_memory,
            "KdfParallelism": user.client_kdf_parallelism,
            "ResetMasterPassword": false,
            "ForcePasswordReset": false,
            "scope": scope_str,
            "unofficialServer": true,
        })),
    )
}

/// `client_credentials` grant — used by the Bitwarden CLI (`bw login
/// --apikey`) and by SCIM tooling. `client_id` carries the principal as
/// `user.{uuid}` (or `organization.{uuid}` for org API keys, which we
/// don't yet implement). `client_secret` is the API key from
/// `/api/accounts/api-key`.
async fn api_key_grant(state: AppState, data: ConnectData) -> (StatusCode, Json<Value>) {
    use subtle::ConstantTimeEq;

    let Some(client_id) = data.client_id.as_deref().filter(|s| !s.is_empty()) else {
        return error_response(StatusCode::BAD_REQUEST, "invalid_request", "client_id is required");
    };
    let Some(client_secret) = data.client_secret.as_deref().filter(|s| !s.is_empty()) else {
        return error_response(StatusCode::BAD_REQUEST, "invalid_request", "client_secret is required");
    };
    let Some(user_uuid) = client_id.strip_prefix("user.") else {
        return error_response(
            StatusCode::BAD_REQUEST,
            "invalid_client",
            "Only user.{uuid} client_id is supported",
        );
    };
    let user = match User::find_by_uuid(&state.db, user_uuid).await {
        Ok(Some(u)) => u,
        Ok(None) => return error_response(StatusCode::BAD_REQUEST, "invalid_client", "User not found"),
        Err(_) => return error_response(StatusCode::INTERNAL_SERVER_ERROR, "server_error", "database error"),
    };
    let api_key = match user.api_key.as_deref() {
        Some(k) if !k.is_empty() => k,
        _ => return error_response(StatusCode::BAD_REQUEST, "invalid_client", "API key not provisioned"),
    };
    if !bool::from(api_key.as_bytes().ct_eq(client_secret.as_bytes())) {
        return error_response(StatusCode::BAD_REQUEST, "invalid_client", "Invalid API key");
    }
    if user.enabled == 0 {
        return error_response(StatusCode::BAD_REQUEST, "invalid_grant", "User disabled");
    }

    // The CLI sends a deviceIdentifier; if missing, mint one tied to
    // "api-key" so we don't churn devices on every CLI invocation.
    let device_identifier = data
        .device_identifier
        .unwrap_or_else(|| format!("api-key-{}", user.uuid));
    let device_name = data.device_name.unwrap_or_else(|| "API Key".into());
    let device_atype: i32 = data.device_type.as_deref().and_then(|s| s.parse().ok()).unwrap_or(14);

    let mut device = match Device::find(&state.db, &device_identifier, &user.uuid).await {
        Ok(Some(d)) => d,
        Ok(None) => {
            let mut d = Device::new(user.uuid.clone(), device_name, device_atype);
            d.uuid = device_identifier;
            d
        }
        Err(_) => {
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "server_error", "database error");
        }
    };
    device.refresh_token = uuid::Uuid::new_v4().to_string();
    if device.save(&state.db).await.is_err() {
        return error_response(StatusCode::INTERNAL_SERVER_ERROR, "server_error", "database error");
    }

    let scope_str = data.scope.as_deref().unwrap_or("api");
    let scope_vec: Vec<String> = scope_str.split_whitespace().map(str::to_owned).collect();
    let claims = LoginJwtClaims::new_for(&state.keys, &device, &user, scope_vec, Some("api-key".into()));
    let access_token = match state.keys.encode(&claims) {
        Ok(t) => t,
        Err(_) => return error_response(StatusCode::INTERNAL_SERVER_ERROR, "server_error", "jwt encode failed"),
    };

    state.telemetry.record("login_apikey", &[("user", &user.uuid)]);
    crate::api::events::log_user_event(
        &state,
        crate::api::events::event_type::USER_LOGGED_IN,
        &user.uuid,
        device_atype,
    )
    .await;

    (
        StatusCode::OK,
        Json(json!({
            "access_token": access_token,
            "expires_in": claims.expires_in(),
            "token_type": "Bearer",
            "Key": user.akey,
            "PrivateKey": user.private_key,
            "Kdf": user.client_kdf_type,
            "KdfIterations": user.client_kdf_iter,
            "KdfMemory": user.client_kdf_memory,
            "KdfParallelism": user.client_kdf_parallelism,
            "ResetMasterPassword": false,
            "ForcePasswordReset": false,
            "scope": scope_str,
            "unofficialServer": true,
        })),
    )
}

async fn refresh_grant(state: AppState, data: ConnectData) -> (StatusCode, Json<Value>) {
    let Some(refresh_token) = data.refresh_token.as_deref().filter(|s| !s.is_empty()) else {
        return error_response(StatusCode::BAD_REQUEST, "invalid_request", "refresh_token is required");
    };

    let mut device = match Device::find_by_refresh_token(&state.db, refresh_token).await {
        Ok(Some(d)) => d,
        Ok(None) => return error_response(StatusCode::BAD_REQUEST, "invalid_grant", "refresh_token is invalid"),
        Err(_) => return error_response(StatusCode::INTERNAL_SERVER_ERROR, "server_error", "database error"),
    };
    let user = match User::find_by_uuid(&state.db, &device.user_uuid).await {
        Ok(Some(u)) => u,
        Ok(None) => return error_response(StatusCode::BAD_REQUEST, "invalid_grant", "user no longer exists"),
        Err(_) => return error_response(StatusCode::INTERNAL_SERVER_ERROR, "server_error", "database error"),
    };
    if user.enabled == 0 {
        return error_response(StatusCode::BAD_REQUEST, "invalid_grant", "user disabled");
    }

    device.refresh_token = uuid::Uuid::new_v4().to_string();
    if device.save(&state.db).await.is_err() {
        return error_response(StatusCode::INTERNAL_SERVER_ERROR, "server_error", "database error");
    }

    let scope_vec: Vec<String> = vec!["api".into(), "offline_access".into()];
    let scope_str = "api offline_access";
    let claims = LoginJwtClaims::new_for(&state.keys, &device, &user, scope_vec, data.client_id);
    let access_token = match state.keys.encode(&claims) {
        Ok(t) => t,
        Err(_) => return error_response(StatusCode::INTERNAL_SERVER_ERROR, "server_error", "jwt encode failed"),
    };

    (
        StatusCode::OK,
        Json(json!({
            "access_token": access_token,
            "expires_in": claims.expires_in(),
            "token_type": "Bearer",
            "refresh_token": device.refresh_token,
            "scope": scope_str,
            "Key": user.akey,
            "PrivateKey": user.private_key,
            "Kdf": user.client_kdf_type,
            "KdfIterations": user.client_kdf_iter,
            "KdfMemory": user.client_kdf_memory,
            "KdfParallelism": user.client_kdf_parallelism,
            "ResetMasterPassword": false,
            "ForcePasswordReset": false,
            "unofficialServer": true,
        })),
    )
}

async fn password_grant(state: AppState, data: ConnectData) -> (StatusCode, Json<Value>) {
    let scope_str = data.scope.as_deref().unwrap_or("");
    let scope_vec: Vec<String> = scope_str.split_whitespace().map(str::to_owned).collect();
    if !scope_vec.iter().any(|s| s == "api") || !scope_vec.iter().any(|s| s == "offline_access") {
        return error_response(
            StatusCode::BAD_REQUEST,
            "invalid_scope",
            "Scope must include both 'api' and 'offline_access'.",
        );
    }

    let Some(username) = data.username.as_ref().map(|s| s.trim().to_owned()) else {
        return error_response(StatusCode::BAD_REQUEST, "invalid_request", "username is required");
    };
    let Some(password) = data.password.as_ref() else {
        return error_response(StatusCode::BAD_REQUEST, "invalid_request", "password is required");
    };

    let user = match User::find_by_email(&state.db, &username).await {
        Ok(Some(u)) => u,
        Ok(None) => {
            return error_response(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "Username or password is incorrect. Try again",
            );
        }
        Err(_) => {
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "server_error", "database error");
        }
    };

    if user.enabled == 0 {
        return error_response(StatusCode::BAD_REQUEST, "invalid_grant", "This user has been disabled");
    }

    if !user.check_valid_password(password) {
        state.telemetry.record("login_failed", &[("user", &user.uuid), ("reason", "bad_password")]);
        crate::api::events::log_user_event(
            &state,
            crate::api::events::event_type::USER_LOGGED_IN_FAILED,
            &user.uuid,
            data.device_type.as_deref().and_then(|s| s.parse().ok()).unwrap_or(14),
        )
        .await;
        return error_response(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "Username or password is incorrect. Try again",
        );
    }

    // 2FA challenge: if the user has any TwoFactor row enabled, the request must
    // carry a valid twoFactorToken matching one of those providers. If absent,
    // we emit the Bitwarden-shaped TwoFactorRequired response so the client knows
    // to prompt the user. This blocks the bypass we previously had.
    let factors = match crate::db::models::TwoFactor::find_by_user(&state.db, &user.uuid).await {
        Ok(v) => v,
        Err(_) => {
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "server_error", "database error");
        }
    };
    let active: Vec<_> = factors.iter().filter(|f| f.enabled == 1 && f.atype < 1000).collect();
    let device_id_for_remember = data.device_identifier.as_deref().unwrap_or("").to_owned();
    if !active.is_empty() {
        let provider_ids: Vec<i32> = active.iter().map(|f| f.atype).collect();

        // First chance to skip the challenge: a previously-issued
        // "remember 2FA" token for this device.
        let remember_skip = match data.two_factor_token.as_deref() {
            Some(t) if !device_id_for_remember.is_empty()
                && data.two_factor_provider == Some(crate::api::two_factor::TWOFACTOR_TYPE_REMEMBER) =>
            {
                crate::api::two_factor::check_remember_token(&state, &user.uuid, &device_id_for_remember, t).await
            }
            _ => false,
        };

        if !remember_skip {
            let Some(provider_id) = data.two_factor_provider else {
                // No provider chosen yet: if email is enrolled, auto-send a fresh
                // login code so the user has it waiting in their inbox by the time
                // they're prompted.
                if provider_ids.contains(&crate::api::two_factor::TWOFACTOR_TYPE_EMAIL) {
                    let _send = crate::api::two_factor::send_login_token(&state, &user.uuid).await;
                }
                // Track the incomplete 2FA so the cron can nudge the user.
                let device_id = data.device_identifier.clone().unwrap_or_default();
                if !device_id.is_empty() {
                    let device_name = data.device_name.clone().unwrap_or_else(|| "unknown".into());
                    let device_atype: i32 = data
                        .device_type
                        .as_deref()
                        .and_then(|s| s.parse().ok())
                        .unwrap_or(14);
                    let row = crate::db::models::TwoFactorIncomplete::new(
                        user.uuid.clone(),
                        device_id,
                        device_name,
                        String::new(),
                        device_atype,
                    );
                    let _save = row.save(&state.db).await;
                }
                return two_factor_required_response(&provider_ids);
            };
            if !provider_ids.contains(&provider_id) {
                return two_factor_required_response(&provider_ids);
            }
            let Some(token) = data.two_factor_token.as_deref().filter(|s| !s.is_empty()) else {
                if provider_id == crate::api::two_factor::TWOFACTOR_TYPE_EMAIL {
                    let _send = crate::api::two_factor::send_login_token(&state, &user.uuid).await;
                }
                return two_factor_required_response(&provider_ids);
            };
            let Some(factor) = active.iter().find(|f| f.atype == provider_id) else {
                return two_factor_required_response(&provider_ids);
            };

            let valid = match provider_id {
                crate::api::two_factor::TWOFACTOR_TYPE_AUTHENTICATOR => {
                    crate::api::two_factor::verify_totp_code(&factor.data, token.trim())
                }
                crate::api::two_factor::TWOFACTOR_TYPE_EMAIL => {
                    crate::api::two_factor::verify_email_login_code(&state, &user.uuid, token.trim()).await
                }
                3 => {
                    // YubiKey OTP — atype = 3 in Bitwarden's enum.
                    crate::api::two_factor::verify_yubikey_login_code(&state, &user.uuid, token.trim()).await
                }
                7 => {
                    // WebAuthn — atype = 7. The token is the serialized
                    // assertion. Without full passkey-rs verification we
                    // accept any non-empty token whose credential prefix
                    // is a registered credential id.
                    crate::api::webauthn::verify_webauthn_login(&state, &user.uuid, token.trim()).await
                }
                _ => false,
            };
            if !valid {
                state.telemetry.record(
                    "login_2fa_invalid",
                    &[("user", &user.uuid), ("provider", &provider_id.to_string())],
                );
                let device_atype: i32 = data
                    .device_type
                    .as_deref()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(14);
                crate::api::events::log_user_event(
                    &state,
                    crate::api::events::event_type::USER_LOGGED_IN_FAILED_2FA,
                    &user.uuid,
                    device_atype,
                )
                .await;
                return error_response(StatusCode::BAD_REQUEST, "invalid_grant", "Invalid two-factor code");
            }
            // 2FA passed: clear any pending incomplete-2FA tracking row so the
            // cron doesn't nudge the user about an already-completed login.
            let device_id = data.device_identifier.clone().unwrap_or_default();
            if !device_id.is_empty()
                && let Ok(Some(row)) =
                    crate::db::models::TwoFactorIncomplete::find(&state.db, &user.uuid, &device_id).await
            {
                let _del = row.delete(&state.db).await;
            }
        }
    }

    // Resolve device. If the client sends a deviceIdentifier we look it up; if it's
    // missing we create a fresh ephemeral one for this login. Persist any new device.
    let device_identifier = data.device_identifier.unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    let device_name = data.device_name.unwrap_or_else(|| "unknown".to_owned());
    let device_atype: i32 = data.device_type.as_deref().and_then(|s| s.parse().ok()).unwrap_or(14);

    let mut device = match Device::find(&state.db, &device_identifier, &user.uuid).await {
        Ok(Some(d)) => d,
        Ok(None) => {
            let mut d = Device::new(user.uuid.clone(), device_name, device_atype);
            d.uuid = device_identifier;
            d
        }
        Err(_) => {
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "server_error", "database error");
        }
    };

    // Issue a fresh refresh_token on every successful login.
    device.refresh_token = uuid::Uuid::new_v4().to_string();
    if device.save(&state.db).await.is_err() {
        return error_response(StatusCode::INTERNAL_SERVER_ERROR, "server_error", "database error");
    }

    let claims = LoginJwtClaims::new_for(&state.keys, &device, &user, scope_vec, data.client_id);
    let access_token = match state.keys.encode(&claims) {
        Ok(t) => t,
        Err(_) => return error_response(StatusCode::INTERNAL_SERVER_ERROR, "server_error", "jwt encode failed"),
    };

    state.telemetry.record("login_success", &[("user", &user.uuid)]);
    crate::api::events::log_user_event(
        &state,
        crate::api::events::event_type::USER_LOGGED_IN,
        &user.uuid,
        device_atype,
    )
    .await;

    let has_master_password = !user.password_hash.is_empty();

    // Bitwarden 2025.8+ web/mobile clients read keys from these structured
    // fields rather than the legacy top-level Key/PrivateKey. The legacy
    // fields are still emitted for older clients. Shape mirrors upstream's
    // `authenticated_response`.
    let master_password_unlock = if has_master_password {
        json!({
            "Kdf": {
                "KdfType": user.client_kdf_type,
                "Iterations": user.client_kdf_iter,
                "Memory": user.client_kdf_memory,
                "Parallelism": user.client_kdf_parallelism,
            },
            "MasterKeyEncryptedUserKey": user.akey,
            "MasterKeyWrappedUserKey": user.akey,
            "Salt": user.email,
        })
    } else {
        Value::Null
    };

    let account_keys = if user.private_key.is_some() {
        json!({
            "publicKeyEncryptionKeyPair": {
                "wrappedPrivateKey": user.private_key,
                "publicKey": user.public_key,
                "Object": "publicKeyEncryptionKeyPair",
            },
            "Object": "privateKeys",
        })
    } else {
        Value::Null
    };

    let mut body = json!({
        "access_token": access_token,
        "expires_in": claims.expires_in(),
        "token_type": "Bearer",
        "refresh_token": device.refresh_token,
        "PrivateKey": user.private_key,
        "Kdf": user.client_kdf_type,
        "KdfIterations": user.client_kdf_iter,
        "KdfMemory": user.client_kdf_memory,
        "KdfParallelism": user.client_kdf_parallelism,
        "ResetMasterPassword": false,
        "ForcePasswordReset": false,
        "MasterPasswordPolicy": { "Object": "masterPasswordPolicy" },
        "scope": scope_str,
        "unofficialServer": true,
        "AccountKeys": account_keys,
        "UserDecryptionOptions": {
            "HasMasterPassword": has_master_password,
            "MasterPasswordUnlock": master_password_unlock,
            "Object": "userDecryptionOptions",
        },
    });
    if !user.akey.is_empty() {
        body["Key"] = Value::String(user.akey.clone());
    }

    // Issue a 2FA-remember token if the client asked for one and the user
    // actually completed a real 2FA challenge this login (i.e. they have any
    // active factor). Mirrors upstream's `TwoFactorToken` field.
    if data.two_factor_remember == Some(1)
        && let Ok(facs) = crate::db::models::TwoFactor::find_by_user(&state.db, &user.uuid).await
        && facs.iter().any(|f| f.enabled == 1 && f.atype < 1000 && f.atype != crate::api::two_factor::TWOFACTOR_TYPE_REMEMBER)
    {
        let tok = crate::api::two_factor::issue_remember_token(&state, &user.uuid, &device.uuid).await;
        body["TwoFactorToken"] = Value::String(tok);
    }

    (StatusCode::OK, Json(body))
}
