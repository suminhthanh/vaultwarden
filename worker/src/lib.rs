#![recursion_limit = "256"]

use axum::{
    Json, Router,
    extract::{Path, State as AxumState},
    http::{HeaderName, HeaderValue, StatusCode, header},
    routing::{delete, get, post},
};
use chrono::{Duration, NaiveDateTime, SecondsFormat, Utc};
use serde::Deserialize;
use serde_json::{Value, json};
use std::sync::Arc;
use tower_http::{cors::{Any, CorsLayer}, set_header::SetResponseHeaderLayer};
use tower_service::Service;
use worker::*;

mod api;
mod auth;
mod config;
mod crypto;
mod db;
mod mail;
mod observability;
mod ratelimit;
mod templates;

use crate::auth::{JwtKeys, LoginJwtClaims};
use crate::db::models::{Cipher, Device, Folder, Membership, Organization, User};

const VAULTWARDEN_VERSION: &str = "1.0.0";

#[derive(Clone)]
pub(crate) struct AppState {
    pub db: Arc<D1Database>,
    pub keys: Arc<JwtKeys>,
    pub vars: Arc<std::collections::HashMap<String, String>>,
    pub attachments: Arc<Bucket>,
    pub web_vault: Arc<Bucket>,
    pub icons: Arc<Bucket>,
    pub sends: Arc<Bucket>,
    pub user_notifications: Arc<ObjectNamespace>,
    pub anon_notifications: Arc<ObjectNamespace>,
    pub ratelimit_kv: Arc<KvStore>,
    #[allow(dead_code)]
    pub config_kv: Arc<KvStore>,
    pub mail: Arc<mail::Provider>,
    pub mail_from: Arc<(String, String)>,
    pub telemetry: observability::Telemetry,
}

impl AppState {
    pub fn env_var(&self, name: &str) -> Option<String> {
        self.vars.get(name).cloned()
    }
}

fn debug_routes_enabled(env: &Env) -> bool {
    !matches!(env.var("VAULTWARDEN_ENV").map(|v| v.to_string()).as_deref(), Ok("production"))
}

fn router(state: AppState, allow_debug: bool) -> Router {
    let public = Router::new()
        .route("/alive", get(alive))
        .route("/api/alive", get(alive))
        .route("/api/now", get(now))
        .route("/api/version", get(version));

    let api = Router::new()
        .merge(api::identity::routes())
        .merge(api::accounts::routes())
        .merge(api::ciphers::routes())
        .merge(api::folders::routes())
        .merge(api::sync::routes())
        .merge(api::meta::routes())
        .merge(api::collections::routes())
        .merge(api::organizations::routes())
        .merge(api::two_factor::routes())
        .merge(api::webauthn::routes())
        .merge(api::attachments::routes())
        .merge(api::sends::routes())
        .merge(api::notifications::routes())
        .merge(api::admin::routes())
        .merge(api::icons::routes())
        .merge(api::auth_requests::routes())
        .merge(api::devices::routes())
        .merge(api::events::routes())
        .merge(api::emergency_access::routes())
        .merge(api::policies::routes())
        .with_state(state.clone());

    let mut app = public.merge(api).merge(api::web_vault::routes().with_state(state.clone()));

    if allow_debug {
        app = app.merge(debug_routes(state));
    }

    app.layer(SetResponseHeaderLayer::if_not_present(
        HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    ))
    .layer(SetResponseHeaderLayer::if_not_present(
        HeaderName::from_static("referrer-policy"),
        HeaderValue::from_static("same-origin"),
    ))
    .layer(SetResponseHeaderLayer::if_not_present(
        HeaderName::from_static("x-frame-options"),
        HeaderValue::from_static("SAMEORIGIN"),
    ))
    .layer(
        CorsLayer::new()
            .allow_origin(Any)
            .allow_methods(Any)
            .allow_headers([
                header::AUTHORIZATION,
                header::CONTENT_TYPE,
                header::ACCEPT,
                HeaderName::from_static("device-type"),
                HeaderName::from_static("bitwarden-client-name"),
                HeaderName::from_static("bitwarden-client-version"),
            ]),
    )
}

fn debug_routes(state: AppState) -> Router {
    Router::new()
        .route("/_test/users/by-email/{email}", get(test_get_user_by_email))
        .route("/_test/users", post(test_create_user))
        .route("/_test/users/{uuid}", delete(test_delete_user))
        .route("/_test/ciphers", post(test_create_cipher))
        .route("/_test/ciphers/{uuid}", get(test_get_cipher).delete(test_delete_cipher))
        .route("/_test/users/{user_uuid}/ciphers", get(test_list_user_ciphers))
        .route("/_test/folders", post(test_create_folder))
        .route("/_test/folders/{uuid}", get(test_get_folder).delete(test_delete_folder))
        .route("/_test/users/{user_uuid}/folders", get(test_list_user_folders))
        .route("/_test/orgs", post(test_create_org))
        .route("/_test/orgs/{uuid}", get(test_get_org).delete(test_delete_org))
        .route("/_test/memberships", post(test_create_membership))
        .route("/_test/memberships/{uuid}", delete(test_delete_membership))
        .route("/_test/orgs/{org_uuid}/memberships/by-user/{user_uuid}", get(test_get_membership))
        .route("/_test/jwt/roundtrip", post(test_jwt_roundtrip))
        .route(
            "/_test/users/{uuid}/secrets",
            get(test_get_user_secrets).put(test_set_user_secrets),
        )
        .route("/_test/users/{uuid}/password", post(test_set_password))
        .route("/_test/users/{uuid}/password/verify", post(test_verify_password))
        .route("/_test/notify/{user_uuid}", post(test_notify_user))
        .route("/_test/mail/send", post(test_send_mail))
        .route("/_test/mail/render/{*template}", post(test_render_template))
        .with_state(state)
}

#[worker::send]
async fn test_render_template(
    Path(template): Path<String>,
    Json(ctx): Json<Value>,
) -> std::result::Result<Json<Value>, (StatusCode, Json<Value>)> {
    match templates::render_subject_body(&template, &ctx) {
        Ok((subject, body)) => Ok(Json(json!({ "subject": subject, "body": body }))),
        Err(e) => Err((StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": e })))),
    }
}

#[derive(serde::Deserialize)]
struct TestMailBody {
    to: String,
    subject: String,
    text: String,
}

#[worker::send]
async fn test_send_mail(
    AxumState(state): AxumState<AppState>,
    Json(body): Json<TestMailBody>,
) -> std::result::Result<Json<Value>, (StatusCode, Json<Value>)> {
    let (from_email, from_name) = state.mail_from.as_ref().clone();
    let msg = mail::MailMessage {
        from_email,
        from_name,
        to: body.to,
        subject: body.subject,
        text: body.text,
        html: None,
    };
    match state.mail.send(&msg).await {
        Ok(()) => Ok(Json(json!({ "ok": true }))),
        Err(e) => Err((StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": e.to_string() })))),
    }
}

#[derive(serde::Deserialize)]
struct NotifyTestBody {
    kind: i32,
    payload_id: String,
}

#[worker::send]
async fn test_notify_user(
    AxumState(state): AxumState<AppState>,
    Path(user_uuid): Path<String>,
    Json(body): Json<NotifyTestBody>,
) -> Json<Value> {
    api::notify::notify_user(&state, &user_uuid, body.kind, &body.payload_id).await;
    Json(json!({ "ok": true }))
}

async fn alive() -> Json<String> {
    Json(format_date(&Utc::now().naive_utc()))
}

async fn now() -> Json<String> {
    Json(format_date(&Utc::now().naive_utc()))
}

async fn version() -> Json<&'static str> {
    Json(VAULTWARDEN_VERSION)
}

#[derive(Deserialize)]
struct CreateUser {
    email: String,
    name: Option<String>,
}

#[worker::send]
async fn test_create_user(
    AxumState(state): AxumState<AppState>,
    Json(body): Json<CreateUser>,
) -> std::result::Result<Json<Value>, StatusCode> {
    let mut user = User::new(&body.email, body.name);
    user.save(&state.db).await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(json!({ "uuid": user.uuid, "email": user.email, "name": user.name })))
}

#[worker::send]
async fn test_get_user_by_email(
    AxumState(state): AxumState<AppState>,
    Path(email): Path<String>,
) -> std::result::Result<Json<Value>, StatusCode> {
    let user = User::find_by_email(&state.db, &email)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;
    Ok(Json(json!({ "uuid": user.uuid, "email": user.email, "name": user.name })))
}

#[worker::send]
async fn test_delete_user(
    AxumState(state): AxumState<AppState>,
    Path(uuid): Path<String>,
) -> std::result::Result<StatusCode, StatusCode> {
    let user = User::find_by_uuid(&state.db, &uuid)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;
    user.delete(&state.db).await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
struct CreateCipher {
    user_uuid: String,
    name: String,
    atype: i32,
    data: String,
}

fn cipher_json(c: &Cipher) -> Value {
    json!({
        "uuid": c.uuid,
        "user_uuid": c.user_uuid,
        "organization_uuid": c.organization_uuid,
        "atype": c.atype,
        "name": c.name,
        "data": c.data,
    })
}

#[worker::send]
async fn test_create_cipher(
    AxumState(state): AxumState<AppState>,
    Json(body): Json<CreateCipher>,
) -> std::result::Result<Json<Value>, StatusCode> {
    let mut cipher = Cipher::new(body.atype, body.name);
    cipher.user_uuid = Some(body.user_uuid);
    cipher.data = body.data;
    cipher.save(&state.db).await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(cipher_json(&cipher)))
}

#[worker::send]
async fn test_get_cipher(
    AxumState(state): AxumState<AppState>,
    Path(uuid): Path<String>,
) -> std::result::Result<Json<Value>, StatusCode> {
    let cipher = Cipher::find_by_uuid(&state.db, &uuid)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;
    Ok(Json(cipher_json(&cipher)))
}

#[worker::send]
async fn test_delete_cipher(
    AxumState(state): AxumState<AppState>,
    Path(uuid): Path<String>,
) -> std::result::Result<StatusCode, StatusCode> {
    let cipher = Cipher::find_by_uuid(&state.db, &uuid)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;
    cipher.delete(&state.db).await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(StatusCode::NO_CONTENT)
}

#[worker::send]
async fn test_list_user_ciphers(
    AxumState(state): AxumState<AppState>,
    Path(user_uuid): Path<String>,
) -> std::result::Result<Json<Value>, StatusCode> {
    let ciphers = Cipher::find_owned_by_user(&state.db, &user_uuid)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(Value::Array(ciphers.iter().map(cipher_json).collect())))
}

#[derive(Deserialize)]
struct CreateFolder {
    user_uuid: String,
    name: String,
}

fn folder_json(f: &Folder) -> Value {
    json!({ "uuid": f.uuid, "user_uuid": f.user_uuid, "name": f.name })
}

#[worker::send]
async fn test_create_folder(
    AxumState(state): AxumState<AppState>,
    Json(body): Json<CreateFolder>,
) -> std::result::Result<Json<Value>, StatusCode> {
    let mut folder = Folder::new(body.user_uuid, body.name);
    folder.save(&state.db).await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(folder_json(&folder)))
}

#[worker::send]
async fn test_get_folder(
    AxumState(state): AxumState<AppState>,
    Path(uuid): Path<String>,
) -> std::result::Result<Json<Value>, StatusCode> {
    let folder = Folder::find_by_uuid(&state.db, &uuid)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;
    Ok(Json(folder_json(&folder)))
}

#[worker::send]
async fn test_delete_folder(
    AxumState(state): AxumState<AppState>,
    Path(uuid): Path<String>,
) -> std::result::Result<StatusCode, StatusCode> {
    let folder = Folder::find_by_uuid(&state.db, &uuid)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;
    folder.delete(&state.db).await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(StatusCode::NO_CONTENT)
}

#[worker::send]
async fn test_list_user_folders(
    AxumState(state): AxumState<AppState>,
    Path(user_uuid): Path<String>,
) -> std::result::Result<Json<Value>, StatusCode> {
    let folders =
        Folder::find_by_user(&state.db, &user_uuid).await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(Value::Array(folders.iter().map(folder_json).collect())))
}

#[derive(Deserialize)]
struct CreateOrg {
    name: String,
    billing_email: String,
}

fn org_json(o: &Organization) -> Value {
    json!({ "uuid": o.uuid, "name": o.name, "billing_email": o.billing_email })
}

#[worker::send]
async fn test_create_org(
    AxumState(state): AxumState<AppState>,
    Json(body): Json<CreateOrg>,
) -> std::result::Result<Json<Value>, StatusCode> {
    let org = Organization::new(body.name, body.billing_email);
    org.save(&state.db).await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(org_json(&org)))
}

#[worker::send]
async fn test_get_org(
    AxumState(state): AxumState<AppState>,
    Path(uuid): Path<String>,
) -> std::result::Result<Json<Value>, StatusCode> {
    let org = Organization::find_by_uuid(&state.db, &uuid)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;
    Ok(Json(org_json(&org)))
}

#[worker::send]
async fn test_delete_org(
    AxumState(state): AxumState<AppState>,
    Path(uuid): Path<String>,
) -> std::result::Result<StatusCode, StatusCode> {
    let org = Organization::find_by_uuid(&state.db, &uuid)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;
    org.delete(&state.db).await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
struct CreateMembership {
    user_uuid: String,
    org_uuid: String,
    akey: String,
    atype: i32,
    status: i32,
    #[serde(default)]
    access_all: Option<bool>,
}

fn membership_json(m: &Membership) -> Value {
    json!({
        "uuid": m.uuid,
        "user_uuid": m.user_uuid,
        "org_uuid": m.org_uuid,
        "atype": m.atype,
        "status": m.status,
    })
}

#[worker::send]
async fn test_create_membership(
    AxumState(state): AxumState<AppState>,
    Json(body): Json<CreateMembership>,
) -> std::result::Result<Json<Value>, StatusCode> {
    let mut m = Membership::new(body.user_uuid, body.org_uuid, body.akey, body.atype, body.status);
    // Test fixture default: grant access_all so confirmed members see org-owned
    // ciphers without having to also wire per-collection ACL in every test.
    m.access_all = if body.access_all.unwrap_or(true) { 1 } else { 0 };
    m.save(&state.db).await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(membership_json(&m)))
}

#[worker::send]
async fn test_get_membership(
    AxumState(state): AxumState<AppState>,
    Path((org_uuid, user_uuid)): Path<(String, String)>,
) -> std::result::Result<Json<Value>, StatusCode> {
    let m = Membership::find_by_user_and_org(&state.db, &user_uuid, &org_uuid)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;
    Ok(Json(membership_json(&m)))
}

#[worker::send]
async fn test_delete_membership(
    AxumState(state): AxumState<AppState>,
    Path(uuid): Path<String>,
) -> std::result::Result<StatusCode, StatusCode> {
    let m = Membership::find_by_uuid(&state.db, &uuid)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;
    m.delete(&state.db).await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
struct PasswordBody {
    password: String,
}

#[worker::send]
async fn test_set_password(
    AxumState(state): AxumState<AppState>,
    Path(uuid): Path<String>,
    Json(body): Json<PasswordBody>,
) -> std::result::Result<Json<Value>, StatusCode> {
    let mut user = User::find_by_uuid(&state.db, &uuid)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;
    user.set_password(&body.password);
    user.save(&state.db).await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(json!({
        "password_hash_len": user.password_hash.len(),
        "salt_len": user.salt.len(),
        "iterations": user.password_iterations,
    })))
}

#[worker::send]
async fn test_verify_password(
    AxumState(state): AxumState<AppState>,
    Path(uuid): Path<String>,
    Json(body): Json<PasswordBody>,
) -> std::result::Result<Json<Value>, StatusCode> {
    let user = User::find_by_uuid(&state.db, &uuid)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;
    Ok(Json(json!({ "valid": user.check_valid_password(&body.password) })))
}

#[derive(Deserialize)]
struct SetUserSecretsBody {
    password_hash_b64: String,
    salt_b64: String,
}

#[derive(Deserialize)]
struct JwtRoundTripInput {
    user_uuid: String,
    device_uuid: String,
    device_atype: i32,
}

#[worker::send]
async fn test_set_user_secrets(
    AxumState(state): AxumState<AppState>,
    Path(uuid): Path<String>,
    Json(body): Json<SetUserSecretsBody>,
) -> std::result::Result<Json<Value>, StatusCode> {
    use base64::Engine as _;
    let mut user = User::find_by_uuid(&state.db, &uuid)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;
    user.password_hash = base64::engine::general_purpose::STANDARD
        .decode(&body.password_hash_b64)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    user.salt = base64::engine::general_purpose::STANDARD
        .decode(&body.salt_b64)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    user.save(&state.db).await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(json!({ "ok": true })))
}

#[worker::send]
async fn test_get_user_secrets(
    AxumState(state): AxumState<AppState>,
    Path(uuid): Path<String>,
) -> std::result::Result<Json<Value>, StatusCode> {
    use base64::Engine as _;
    let user = User::find_by_uuid(&state.db, &uuid)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;
    Ok(Json(json!({
        "password_hash_b64": base64::engine::general_purpose::STANDARD.encode(&user.password_hash),
        "salt_b64": base64::engine::general_purpose::STANDARD.encode(&user.salt),
        "password_hash_len": user.password_hash.len(),
        "salt_len": user.salt.len(),
    })))
}#[worker::send]
async fn test_jwt_roundtrip(
    AxumState(state): AxumState<AppState>,
    Json(body): Json<JwtRoundTripInput>,
) -> std::result::Result<Json<Value>, StatusCode> {
    let mut user = User::new("jwt-test@example.com", Some("JWT".into()));
    user.uuid = body.user_uuid;
    let mut device = Device::new(user.uuid.clone(), "TestDevice".into(), body.device_atype);
    device.uuid = body.device_uuid;

    let claims = LoginJwtClaims::new_for(
        &state.keys,
        &device,
        &user,
        vec!["api".into(), "offline_access".into()],
        Some("web".into()),
    );
    let token = state.keys.encode(&claims).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let decoded: LoginJwtClaims = state
        .keys
        .decode(&token, &state.keys.login_issuer)
        .map_err(|_| StatusCode::UNAUTHORIZED)?;

    Ok(Json(json!({
        "token": token,
        "iss": decoded.iss,
        "sub": decoded.sub,
        "device": decoded.device,
        "scope": decoded.scope,
        "expires_in": claims.expires_in(),
    })))
}

fn format_date(dt: &NaiveDateTime) -> String {
    dt.and_utc().to_rfc3339_opts(SecondsFormat::Micros, true)
}

#[event(fetch)]
async fn fetch(req: HttpRequest, env: Env, _ctx: Context) -> Result<axum::http::Response<axum::body::Body>> {
    console_error_panic_hook::set_once();
    let db = env.d1("DB")?;
    let keys = JwtKeys::from_env(&env).map_err(|e| Error::RustError(e.to_string()))?;

    let mut vars = std::collections::HashMap::new();
    for name in ["DOMAIN", "VAULTWARDEN_ENV"] {
        if let Ok(v) = env.var(name) {
            vars.insert(name.to_owned(), v.to_string());
        }
    }
    if let Ok(t) = env.secret("ADMIN_TOKEN") {
        vars.insert("ADMIN_TOKEN".to_owned(), t.to_string());
    }

    let state = AppState {
        db: Arc::new(db),
        keys: Arc::new(keys),
        vars: Arc::new(vars),
        attachments: Arc::new(env.bucket("ATTACHMENTS")?),
        web_vault: Arc::new(env.bucket("WEB_VAULT")?),
        icons: Arc::new(env.bucket("ICONS")?),
        sends: Arc::new(env.bucket("SENDS")?),
        user_notifications: Arc::new(env.durable_object("USER_NOTIFICATIONS")?),
        anon_notifications: Arc::new(env.durable_object("ANON_NOTIFICATIONS")?),
        ratelimit_kv: Arc::new(env.kv("RATELIMIT_KV")?),
        config_kv: Arc::new(env.kv("CONFIG_KV")?),
        mail: Arc::new(mail::provider_from_env(&env)),
        mail_from: Arc::new(mail::from_address(&env)),
        telemetry: observability::Telemetry::from_env(&env),
    };

    let allow_debug = debug_routes_enabled(&env);
    Ok(router(state, allow_debug).call(req).await?)
}

#[event(scheduled)]
async fn scheduled(event: ScheduledEvent, env: Env, _ctx: ScheduleContext) {
    console_error_panic_hook::set_once();
    let cron = event.cron();
    if let Err(e) = run_purges(&env, &cron).await {
        console_error!("scheduled purge failed: {e}");
    }
}

async fn run_purges(env: &Env, cron: &str) -> Result<()> {
    use crate::db::models::{
        AuthRequest, Cipher, EmergencyAccess, Event, Send, SsoAuth, TwoFactorDuoContext,
    };

    let db = env.d1("DB")?;
    let now = Utc::now();
    let now_iso = now.to_rfc3339_opts(SecondsFormat::Micros, true);

    // Sends every 5 minutes — they expire frequently and need quick cleanup.
    if cron.starts_with("*/5 ") {
        // Collect file-send UUIDs about to expire so we can sweep R2 first.
        if let Ok(uuids) = Send::expired_file_send_uuids(&db, &now_iso).await
            && !uuids.is_empty()
        {
            let bucket = env.bucket("SENDS")?;
            for uuid in uuids {
                let prefix = format!("{uuid}/");
                if let Ok(list) = bucket.list().prefix(prefix).execute().await {
                    for obj in list.objects() {
                        let _r2 = bucket.delete(obj.key()).await;
                    }
                }
            }
        }
        match Send::purge_expired(&db, &now_iso).await {
            Ok(n) => console_log!("[cron 5m] purged {n} expired sends"),
            Err(e) => console_error!("[cron 5m] sends purge failed: {e}"),
        }
        return Ok(());
    }

    // Hourly — older trashed ciphers (>30 days), stale auth_requests (>1 day),
    // emergency-access auto-approve, and Duo OIDC context cleanup.
    if cron.starts_with("0 * ") {
        let trash_cutoff =
            (now - Duration::days(30)).to_rfc3339_opts(SecondsFormat::Micros, true);
        // Clean up R2 attachment objects for trash-purged ciphers + their
        // attachment rows. We do this before the cipher purge so the rows are
        // still visible while we collect keys.
        if let Ok(keys) = Cipher::trashed_attachment_keys(&db, &trash_cutoff).await
            && !keys.is_empty()
        {
            let bucket = env.bucket("ATTACHMENTS")?;
            for (cipher_uuid, attachment_id) in &keys {
                let key = format!("{cipher_uuid}/{attachment_id}");
                let _r2 = bucket.delete(&key).await;
            }
            // Drop the rows now that R2 is clean. Use a single statement so we
            // don't make N round-trips when the trash backlog is large.
            let _rows = db
                .prepare(
                    "DELETE FROM attachments WHERE cipher_uuid IN (\
                     SELECT uuid FROM ciphers WHERE deleted_at IS NOT NULL AND deleted_at < ?1)",
                )
                .bind(&[wasm_bindgen::JsValue::from_str(&trash_cutoff)])?
                .run()
                .await;
            console_log!("[cron 1h] cleared R2 for {} trashed attachments", keys.len());
        }
        match Cipher::purge_trashed_before(&db, &trash_cutoff).await {
            Ok(n) => console_log!("[cron 1h] purged {n} trashed ciphers"),
            Err(e) => console_error!("[cron 1h] cipher purge failed: {e}"),
        }
        let auth_cutoff =
            (now - Duration::days(1)).to_rfc3339_opts(SecondsFormat::Micros, true);
        if let Err(e) = AuthRequest::purge_old(&db, &auth_cutoff).await {
            console_error!("[cron 1h] auth_request purge failed: {e}");
        } else {
            console_log!("[cron 1h] purged old auth_requests");
        }

        match EmergencyAccess::auto_approve_due(&db).await {
            Ok(n) => console_log!("[cron 1h] auto-approved {n} emergency access requests"),
            Err(e) => console_error!("[cron 1h] EA auto-approve failed: {e}"),
        }

        // Email reminders for pending recovery requests. Best-effort — if mail
        // sending fails for one row, keep going for the rest.
        if let Ok(reminders) = EmergencyAccess::pending_reminders(&db).await {
            let mut sent = 0u32;
            let mail = mail::provider_from_env(env);
            let from = mail::from_address(env);
            for mut row in reminders {
                let Some(grantor_uuid) = row.grantor_uuid.clone() else { continue };
                let Some(grantee_uuid) = row.grantee_uuid.clone() else { continue };
                let grantor = User::find_by_uuid(&db, &grantor_uuid).await.ok().flatten();
                let grantee = User::find_by_uuid(&db, &grantee_uuid).await.ok().flatten();
                let (Some(grantor), Some(grantee)) = (grantor, grantee) else { continue };
                let _send = mail
                    .send(&mail::MailMessage {
                        from_email: from.0.clone(),
                        from_name: from.1.clone(),
                        to: grantor.email.clone(),
                        subject: "Pending emergency access request".into(),
                        text: format!(
                            "{} has requested emergency access to your Vaultwarden account. Approve or reject before the wait window expires.",
                            grantee.email
                        ),
                        html: None,
                    })
                    .await;
                row.last_notification_at = Some(now_iso.clone());
                let _save = row.save(&db).await;
                sent += 1;
            }
            if sent > 0 {
                console_log!("[cron 1h] sent {sent} emergency-access reminders");
            }
        }

        let duo_now_secs = now.timestamp();
        if let Err(e) = TwoFactorDuoContext::purge_expired(&db, duo_now_secs).await {
            console_error!("[cron 1h] Duo context purge failed: {e}");
        } else {
            console_log!("[cron 1h] purged expired Duo contexts");
        }

        // Incomplete-2FA reminders: any login that's been stuck on the 2FA
        // prompt for 15 minutes earns a notification email. We scan + delete
        // matching rows so each row triggers at most one email.
        let stale_2fa_cutoff =
            (now - Duration::minutes(15)).to_rfc3339_opts(SecondsFormat::Micros, true);
        #[derive(serde::Deserialize)]
        struct StaleTfa {
            user_uuid: String,
            device_name: String,
            ip_address: String,
            #[allow(dead_code)]
            login_time: String,
            device_uuid: String,
        }
        if let Ok(stmt) = db
            .prepare(
                "SELECT user_uuid, device_uuid, device_name, login_time, ip_address \
                 FROM twofactor_incomplete WHERE login_time <= ?1",
            )
            .bind(&[wasm_bindgen::JsValue::from_str(&stale_2fa_cutoff)])
        {
            let rows: Vec<StaleTfa> = stmt
                .all()
                .await
                .ok()
                .and_then(|r| r.results::<StaleTfa>().ok())
                .unwrap_or_default();
            if !rows.is_empty() {
                let mail = mail::provider_from_env(env);
                let from = mail::from_address(env);
                let host = env.var("DOMAIN").map(|v| v.to_string()).unwrap_or_default();
                let mut sent = 0u32;
                for row in rows {
                    if let Ok(Some(user)) =
                        User::find_by_uuid(&db, &row.user_uuid).await
                    {
                        let _send = mail
                            .send(&mail::MailMessage {
                                from_email: from.0.clone(),
                                from_name: from.1.clone(),
                                to: user.email,
                                subject: "Incomplete two-factor sign-in attempt".into(),
                                text: format!(
                                    "We saw an unfinished sign-in attempt on {} from {} to your Vaultwarden account at {host}. If this wasn't you, change your password.",
                                    row.device_name,
                                    if row.ip_address.is_empty() { "an unknown IP" } else { row.ip_address.as_str() },
                                ),
                                html: None,
                            })
                            .await;
                    }
                    let _del = db
                        .prepare(
                            "DELETE FROM twofactor_incomplete WHERE user_uuid = ?1 AND device_uuid = ?2",
                        )
                        .bind(&[
                            wasm_bindgen::JsValue::from_str(&row.user_uuid),
                            wasm_bindgen::JsValue::from_str(&row.device_uuid),
                        ])?
                        .run()
                        .await;
                    sent += 1;
                }
                if sent > 0 {
                    console_log!("[cron 1h] sent {sent} incomplete-2FA reminders");
                }
            }
        }
        return Ok(());
    }

    // Daily — events older than 30 days, expired SSO auth rows, daily heartbeat.
    if cron.starts_with("0 0 ") {
        let event_cutoff =
            (now - Duration::days(30)).to_rfc3339_opts(SecondsFormat::Micros, true);
        if let Err(e) = Event::delete_old(&db, &event_cutoff).await {
            console_error!("[cron 24h] event purge failed: {e}");
        } else {
            console_log!("[cron 24h] purged events older than 30 days");
        }
        let sso_cutoff =
            (now - Duration::hours(1)).to_rfc3339_opts(SecondsFormat::Micros, true);
        if let Err(e) = SsoAuth::purge_old(&db, &sso_cutoff).await {
            console_error!("[cron 24h] sso_auth purge failed: {e}");
        } else {
            console_log!("[cron 24h] purged stale sso_auth rows");
        }
        console_log!("[cron 24h] daily maintenance complete");
        return Ok(());
    }

    Ok(())
}

#[durable_object]
pub struct UserNotificationDO {
    state: State,
}

impl DurableObject for UserNotificationDO {
    fn new(state: State, _env: Env) -> Self {
        Self { state }
    }

    async fn fetch(&self, req: Request) -> Result<Response> {
        let url = req.url()?;
        match url.path() {
            "/connect" => self.handle_connect().await,
            "/broadcast" => self.handle_broadcast(req).await,
            _ => Response::error("not found", 404),
        }
    }

    async fn websocket_message(
        &self,
        _ws: WebSocket,
        _message: WebSocketIncomingMessage,
    ) -> Result<()> {
        // Inbound messages from clients are heartbeats / negotiation — ignore for now.
        Ok(())
    }

    async fn websocket_close(
        &self,
        _ws: WebSocket,
        _code: usize,
        _reason: String,
        _was_clean: bool,
    ) -> Result<()> {
        Ok(())
    }

    async fn websocket_error(&self, _ws: WebSocket, _error: Error) -> Result<()> {
        Ok(())
    }
}

impl UserNotificationDO {
    async fn handle_connect(&self) -> Result<Response> {
        let pair = WebSocketPair::new()?;
        self.state.accept_web_socket(&pair.server);
        Response::from_websocket(pair.client)
    }

    async fn handle_broadcast(&self, mut req: Request) -> Result<Response> {
        let payload = req.text().await?;
        for ws in self.state.get_websockets() {
            let _result = ws.send_with_str(&payload);
        }
        Response::ok("ok")
    }
}

#[durable_object]
pub struct AnonymousNotificationDO {
    state: State,
}

impl DurableObject for AnonymousNotificationDO {
    fn new(state: State, _env: Env) -> Self {
        Self { state }
    }

    async fn fetch(&self, req: Request) -> Result<Response> {
        let url = req.url()?;
        match url.path() {
            "/connect" => {
                let pair = WebSocketPair::new()?;
                self.state.accept_web_socket(&pair.server);
                Response::from_websocket(pair.client)
            }
            "/broadcast" => {
                let mut req = req;
                let payload = req.text().await?;
                for ws in self.state.get_websockets() {
                    let _result = ws.send_with_str(&payload);
                }
                Response::ok("ok")
            }
            _ => Response::error("not found", 404),
        }
    }

    async fn websocket_message(
        &self,
        _ws: WebSocket,
        _message: WebSocketIncomingMessage,
    ) -> Result<()> {
        Ok(())
    }

    async fn websocket_close(
        &self,
        _ws: WebSocket,
        _code: usize,
        _reason: String,
        _was_clean: bool,
    ) -> Result<()> {
        Ok(())
    }

    async fn websocket_error(&self, _ws: WebSocket, _error: Error) -> Result<()> {
        Ok(())
    }
}
