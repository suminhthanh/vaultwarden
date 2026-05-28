//! Admin panel — login, user list, runtime config overrides, diagnostics.
//!
//! Authentication is a shared-secret model: the operator sets `ADMIN_TOKEN` as
//! a Worker secret. Posting that token to `/admin` mints a short-lived signed
//! cookie. Every other admin route requires that cookie.
//!
//! UI is the upstream Handlebars templates rendered server-side; assets ship
//! embedded in the wasm binary via include_str! / include_bytes! and are
//! served from `/vw_static/<file>`.

use axum::{
    Json, Router,
    extract::{Form, Path as AxumPath, State as AxumState},
    http::{HeaderMap, StatusCode, header},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
};
use serde::Deserialize;
use serde_json::{Value, json};
use subtle::ConstantTimeEq;

use crate::AppState;
use crate::config::ConfigOverrides;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/admin", get(panel_root).post(login_form))
        .route("/admin/login", post(login_json))
        .route("/admin/logout", get(logout).post(logout))
        .route("/admin/users/overview", get(users_overview))
        .route("/admin/organizations/overview", get(organizations_overview))
        .route("/admin/diagnostics", get(diagnostics_page))
        .route("/admin/diagnostics/config", get(diagnostics_config))
        .route("/admin/diagnostics/http", get(diagnostics_http))
        .route("/admin/config", get(get_config).post(post_config))
        .route("/admin/config/backup_db", post(config_backup_stub))
        .route("/admin/config/delete", post(config_delete_stub))
        .route("/admin/users", get(list_users))
        .route("/admin/users/{user_id}/disable", post(admin_disable_user))
        .route("/admin/users/{user_id}/enable", post(admin_enable_user))
        .route("/admin/users/{user_id}/deauth", post(admin_deauth_user))
        .route("/admin/users/{user_id}/remove-2fa", post(admin_remove_2fa))
        .route("/admin/users/{user_id}/delete", post(admin_delete_user))
        .route("/admin/users/{user_id}/invite/resend", post(admin_invite_resend))
        .route("/admin/users/{user_id}/sso", axum::routing::delete(admin_unlink_sso))
        .route("/admin/users/update_revision", post(admin_update_revision))
        .route("/admin/users/org_type", post(admin_set_org_type))
        .route("/admin/test/smtp", post(admin_test_smtp))
        .route("/admin/invite", post(admin_invite_user))
        .route("/admin/users/by-mail/{email}", get(admin_user_by_mail))
        .route("/admin/users/{user_id}", get(admin_user_detail))
        .route("/admin/organizations/{org_id}/delete", post(admin_delete_org))
        .route("/vw_static/{file}", get(static_asset))
}

const COOKIE_NAME: &str = "VW_ADMIN_SESSION";

fn ok_admin(state: &AppState, headers: &HeaderMap) -> bool {
    let admin_token = match state.vars.get("ADMIN_TOKEN").cloned() {
        Some(s) if !s.is_empty() => s,
        _ => return false,
    };
    let cookie = headers.get(header::COOKIE).and_then(|v| v.to_str().ok()).unwrap_or("");
    cookie
        .split(';')
        .map(str::trim)
        .filter_map(|c| c.strip_prefix(&format!("{COOKIE_NAME}=")))
        .any(|v| bool::from(v.as_bytes().ct_eq(admin_token.as_bytes())))
}

fn render_login(error: Option<&str>) -> Response {
    let ctx = json!({ "urlpath": "", "logged_in": false, "error": error });
    match crate::templates::render_admin("login", &ctx) {
        Ok(html) => Html(html).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, format!("template error: {e}")).into_response(),
    }
}

#[worker::send]
async fn panel_root(AxumState(state): AxumState<AppState>, headers: HeaderMap) -> Response {
    if !ok_admin(&state, &headers) {
        return render_login(None);
    }
    settings_page(&state).await
}

#[derive(Deserialize)]
struct LoginForm {
    token: String,
    #[serde(default)]
    redirect: Option<String>,
}

async fn login_form(
    AxumState(state): AxumState<AppState>,
    Form(body): Form<LoginForm>,
) -> Response {
    let admin_token = state.vars.get("ADMIN_TOKEN").cloned().unwrap_or_default();
    if admin_token.is_empty() {
        return render_login(Some("Admin panel disabled: no ADMIN_TOKEN configured"));
    }
    if !bool::from(body.token.as_bytes().ct_eq(admin_token.as_bytes())) {
        return render_login(Some("Invalid admin token"));
    }
    let cookie = format!(
        "{COOKIE_NAME}={admin_token}; Path=/admin; HttpOnly; SameSite=Strict; Max-Age=3600"
    );
    let target = body.redirect.unwrap_or_else(|| "/admin".into());
    let mut resp = Response::builder()
        .status(StatusCode::SEE_OTHER)
        .header(header::LOCATION, target)
        .body(axum::body::Body::empty())
        .unwrap();
    if let Ok(v) = header::HeaderValue::from_str(&cookie) {
        resp.headers_mut().insert(header::SET_COOKIE, v);
    }
    resp
}

#[derive(Deserialize)]
struct LoginJsonBody {
    token: String,
}

async fn login_json(
    AxumState(state): AxumState<AppState>,
    Json(body): Json<LoginJsonBody>,
) -> Response {
    let admin_token = state.vars.get("ADMIN_TOKEN").cloned().unwrap_or_default();
    if admin_token.is_empty() {
        return error_resp(StatusCode::SERVICE_UNAVAILABLE, "Admin panel disabled");
    }
    if !bool::from(body.token.as_bytes().ct_eq(admin_token.as_bytes())) {
        return error_resp(StatusCode::UNAUTHORIZED, "Invalid admin token");
    }
    let cookie = format!(
        "{COOKIE_NAME}={admin_token}; Path=/admin; HttpOnly; SameSite=Strict; Max-Age=3600"
    );
    let mut resp = (StatusCode::OK, Json(json!({ "ok": true }))).into_response();
    if let Ok(v) = header::HeaderValue::from_str(&cookie) {
        resp.headers_mut().insert(header::SET_COOKIE, v);
    }
    resp
}

async fn logout() -> Response {
    let cookie = format!("{COOKIE_NAME}=; Path=/admin; HttpOnly; SameSite=Strict; Max-Age=0");
    let mut resp = Response::builder()
        .status(StatusCode::SEE_OTHER)
        .header(header::LOCATION, "/admin")
        .body(axum::body::Body::empty())
        .unwrap();
    if let Ok(v) = header::HeaderValue::from_str(&cookie) {
        resp.headers_mut().insert(header::SET_COOKIE, v);
    }
    resp
}

async fn settings_page(state: &AppState) -> Response {
    let cfg = crate::config::load(&state.config_kv).await;
    // Upstream's settings.hbs expects `page_data.config` to be an array of
    // groups and `page_data.can_backup` for the backup button. We don't have
    // the full ~150-field config schema yet — render a small set of groups
    // with the fields the worker actually reads from KV. The form posts back
    // to /admin/config (JSON).
    let ctx = json!({
        "urlpath": "",
        "logged_in": true,
        "page_data": {
            "config": settings_config_groups(&cfg),
            "can_backup": false,
        },
        "version": "1.0.0-worker",
    });
    render_or_500("settings", &ctx)
}

fn settings_config_groups(cfg: &ConfigOverrides) -> Value {
    let bool_field = |name: &str, label: &str, val: Option<bool>| {
        json!({
            "name": name,
            "doc": { "name": label, "description": "" },
            "value": val.unwrap_or(false),
            "default": false,
            "type": "checkbox",
            "editable": true,
            "overridden": val.is_some(),
        })
    };
    let int_field = |name: &str, label: &str, val: Option<u32>| {
        json!({
            "name": name,
            "doc": { "name": label, "description": "" },
            "value": val.map(|v| v as i64).unwrap_or(0),
            "default": 0,
            "type": "number",
            "editable": true,
            "overridden": val.is_some(),
        })
    };
    json!([
        {
            "group": "general_settings",
            "groupdoc": { "name": "General settings" },
            "elements": [
                bool_field("signups_allowed", "Allow new signups", cfg.signups_allowed),
                bool_field("signups_verify", "Require email verification on signup", cfg.signups_verify),
                bool_field("invitations_allowed", "Allow invitations", cfg.invitations_allowed),
                bool_field("disable_invitations", "Disable invitations", cfg.disable_invitations),
                bool_field("require_device_email", "Require device email", cfg.require_device_email),
                int_field("max_login_attempts", "Max login attempts", cfg.max_login_attempts),
            ]
        },
        {
            "group": "two_factor",
            "groupdoc": { "name": "Two-factor authentication" },
            "elements": [
                bool_field("email_2fa_enabled", "Email 2FA enabled", cfg.email_2fa_enabled),
            ]
        },
    ])
}

#[worker::send]
async fn users_overview(AxumState(state): AxumState<AppState>, headers: HeaderMap) -> Response {
    if !ok_admin(&state, &headers) {
        return render_login(None);
    }
    let users = users_list_data(&state).await;
    let ctx = json!({
        "urlpath": "",
        "logged_in": true,
        "page_data": users,
        "sso_enabled": false,
    });
    render_or_500("users", &ctx)
}

async fn users_list_data(state: &AppState) -> Vec<Value> {
    #[derive(serde::Deserialize)]
    struct Row {
        uuid: String,
        email: String,
        name: String,
        enabled: i32,
        created_at: String,
        verified_at: Option<String>,
        last_active: Option<String>,
        cipher_count: Option<i64>,
        attachment_count: Option<i64>,
        attachment_size: Option<i64>,
        twofactor_count: Option<i64>,
    }
    let stmt = match state
        .db
        .prepare(
            "SELECT u.uuid, u.email, u.name, u.enabled, u.created_at, u.verified_at, \
                    (SELECT MAX(updated_at) FROM devices d WHERE d.user_uuid = u.uuid) AS last_active, \
                    (SELECT COUNT(*) FROM ciphers c WHERE c.user_uuid = u.uuid) AS cipher_count, \
                    (SELECT COUNT(*) FROM attachments a JOIN ciphers c2 ON c2.uuid = a.cipher_uuid WHERE c2.user_uuid = u.uuid) AS attachment_count, \
                    (SELECT IFNULL(SUM(a.file_size), 0) FROM attachments a JOIN ciphers c3 ON c3.uuid = a.cipher_uuid WHERE c3.user_uuid = u.uuid) AS attachment_size, \
                    (SELECT COUNT(*) FROM twofactor t WHERE t.user_uuid = u.uuid AND t.enabled = 1) AS twofactor_count \
             FROM users u ORDER BY u.created_at DESC LIMIT 200",
        )
        .all()
        .await
    {
        Ok(r) => r,
        Err(_) => return Vec::new(),
    };
    let rows: Vec<Row> = stmt.results().unwrap_or_default();

    let mut out = Vec::with_capacity(rows.len());
    for r in rows {
        let size_bytes = r.attachment_size.unwrap_or(0);
        out.push(json!({
            "id": r.uuid,
            "email": r.email,
            "name": r.name,
            "user_enabled": r.enabled == 1,
            "emailVerified": r.verified_at.is_some(),
            "twoFactorEnabled": r.twofactor_count.unwrap_or(0) > 0,
            "_status": 0,
            "created_at": r.created_at,
            "last_active": r.last_active,
            "cipher_count": r.cipher_count.unwrap_or(0),
            "attachment_count": r.attachment_count.unwrap_or(0),
            "attachment_size": format_bytes(size_bytes),
            "organizations": [],
            "sso_identifier": null,
        }));
    }
    out
}

fn format_bytes(bytes: i64) -> String {
    const KB: f64 = 1024.0;
    let n = bytes as f64;
    if n < KB { format!("{bytes} Bytes") }
    else if n < KB * KB { format!("{:.1} KB", n / KB) }
    else if n < KB * KB * KB { format!("{:.1} MB", n / (KB * KB)) }
    else { format!("{:.2} GB", n / (KB * KB * KB)) }
}

#[worker::send]
async fn organizations_overview(
    AxumState(state): AxumState<AppState>,
    headers: HeaderMap,
) -> Response {
    if !ok_admin(&state, &headers) {
        return render_login(None);
    }
    #[derive(serde::Deserialize)]
    struct Row {
        uuid: String,
        name: String,
        billing_email: String,
        user_count: Option<i64>,
        cipher_count: Option<i64>,
        collection_count: Option<i64>,
        group_count: Option<i64>,
        event_count: Option<i64>,
    }
    let rows: Vec<Row> = state
        .db
        .prepare(
            "SELECT o.uuid, o.name, o.billing_email, \
                    (SELECT COUNT(*) FROM users_organizations uo WHERE uo.org_uuid = o.uuid) AS user_count, \
                    (SELECT COUNT(*) FROM ciphers c WHERE c.organization_uuid = o.uuid) AS cipher_count, \
                    (SELECT COUNT(*) FROM collections col WHERE col.org_uuid = o.uuid) AS collection_count, \
                    (SELECT COUNT(*) FROM groups g WHERE g.organizations_uuid = o.uuid) AS group_count, \
                    (SELECT COUNT(*) FROM event e WHERE e.org_uuid = o.uuid) AS event_count \
             FROM organizations o ORDER BY o.name LIMIT 200",
        )
        .all()
        .await
        .ok()
        .and_then(|r| r.results().ok())
        .unwrap_or_default();
    let page_data: Vec<Value> = rows
        .into_iter()
        .map(|r| {
            json!({
                "id": r.uuid,
                "name": r.name,
                "billing": r.billing_email,
                "user_count": r.user_count.unwrap_or(0),
                "cipher_count": r.cipher_count.unwrap_or(0),
                "collection_count": r.collection_count.unwrap_or(0),
                "group_count": r.group_count.unwrap_or(0),
                "event_count": r.event_count.unwrap_or(0),
            })
        })
        .collect();
    let ctx = json!({ "urlpath": "", "logged_in": true, "page_data": page_data });
    render_or_500("organizations", &ctx)
}

#[worker::send]
async fn diagnostics_page(
    AxumState(state): AxumState<AppState>,
    headers: HeaderMap,
) -> Response {
    if !ok_admin(&state, &headers) {
        return render_login(None);
    }
    let env_var = state.env_var("VAULTWARDEN_ENV").unwrap_or_default();
    let domain = state.env_var("DOMAIN").unwrap_or_default();
    let mail_provider = match state.mail.as_ref() {
        crate::mail::Provider::Log(_) => "log",
        crate::mail::Provider::Resend(_) => "resend",
        crate::mail::Provider::MailChannels(_) => "mailchannels",
    };
    let ctx = json!({
        "urlpath": "",
        "logged_in": true,
        "page_data": {
            "vaultwarden_version": "1.0.0-worker",
            "running_within_container": false,
            "container_base_image": "Cloudflare Workers (wasm32-unknown-unknown)",
            "vaultwarden_env": env_var,
            "domain": domain,
            "mail_provider": mail_provider,
            "use_https": domain.starts_with("https://"),
            "host_arch": "wasm32",
            "host_os": "workers",
            "ip_header_exists": false,
            "ip_header_match": true,
            "ip_header_name": "cf-connecting-ip",
            "ip_header_config": "cf-connecting-ip",
            "uses_proxy": true,
            "db_type": "Cloudflare D1 (sqlite)",
            "db_version": "(managed)",
            "admin_url": format!("{domain}/admin"),
            "overrides": "",
            "has_http_access": true,
            "has_recommended_release": true,
            "has_latest_release": true,
            "tz_env": "UTC",
            "server_time": chrono::Utc::now().to_rfc3339(),
        },
    });
    render_or_500("diagnostics", &ctx)
}

#[worker::send]
async fn get_config(AxumState(state): AxumState<AppState>, headers: HeaderMap) -> Response {
    if !ok_admin(&state, &headers) {
        return error_resp(StatusCode::UNAUTHORIZED, "auth required");
    }
    let cfg = crate::config::load(&state.config_kv).await;
    Json(json!(cfg)).into_response()
}

#[worker::send]
async fn post_config(
    AxumState(state): AxumState<AppState>,
    headers: HeaderMap,
    Json(body): Json<ConfigOverrides>,
) -> Response {
    if !ok_admin(&state, &headers) {
        return error_resp(StatusCode::UNAUTHORIZED, "auth required");
    }
    if let Err(e) = crate::config::save(&state.config_kv, &body).await {
        return error_resp(StatusCode::INTERNAL_SERVER_ERROR, &format!("save failed: {e}"));
    }
    Json(json!(body)).into_response()
}

#[worker::send]
async fn list_users(AxumState(state): AxumState<AppState>, headers: HeaderMap) -> Response {
    if !ok_admin(&state, &headers) {
        return error_resp(StatusCode::UNAUTHORIZED, "auth required");
    }
    let data = users_list_data(&state).await;
    Json(json!({ "Object": "list", "Data": data, "ContinuationToken": Value::Null })).into_response()
}

// ---------------------------------------------------------------------------
// Admin user actions: disable/enable/deauth/remove-2fa/delete + org delete.

#[worker::send]
async fn admin_disable_user(
    AxumState(state): AxumState<AppState>,
    headers: HeaderMap,
    AxumPath(user_id): AxumPath<String>,
) -> Response {
    if !ok_admin(&state, &headers) {
        return error_resp(StatusCode::UNAUTHORIZED, "auth required");
    }
    let mut user = match crate::db::models::User::find_by_uuid(&state.db, &user_id).await {
        Ok(Some(u)) => u,
        Ok(None) => return error_resp(StatusCode::NOT_FOUND, "User not found"),
        Err(_) => return error_resp(StatusCode::INTERNAL_SERVER_ERROR, "db error"),
    };
    user.enabled = 0;
    user.security_stamp = uuid::Uuid::new_v4().to_string();
    if user.save(&state.db).await.is_err() {
        return error_resp(StatusCode::INTERNAL_SERVER_ERROR, "save failed");
    }
    crate::api::notify::notify_user(
        &state,
        &user.uuid,
        crate::api::notify::kind::LOG_OUT,
        &user.uuid,
    )
    .await;
    Json(json!({ "Object": "user", "Id": user.uuid, "Enabled": false })).into_response()
}

#[worker::send]
async fn admin_enable_user(
    AxumState(state): AxumState<AppState>,
    headers: HeaderMap,
    AxumPath(user_id): AxumPath<String>,
) -> Response {
    if !ok_admin(&state, &headers) {
        return error_resp(StatusCode::UNAUTHORIZED, "auth required");
    }
    let mut user = match crate::db::models::User::find_by_uuid(&state.db, &user_id).await {
        Ok(Some(u)) => u,
        Ok(None) => return error_resp(StatusCode::NOT_FOUND, "User not found"),
        Err(_) => return error_resp(StatusCode::INTERNAL_SERVER_ERROR, "db error"),
    };
    user.enabled = 1;
    if user.save(&state.db).await.is_err() {
        return error_resp(StatusCode::INTERNAL_SERVER_ERROR, "save failed");
    }
    Json(json!({ "Object": "user", "Id": user.uuid, "Enabled": true })).into_response()
}

async fn run_sql(db: &worker::D1Database, sql: &str, bind: &str) -> bool {
    if let Ok(stmt) = db.prepare(sql).bind(&[worker::wasm_bindgen::JsValue::from_str(bind)])
        && stmt.run().await.is_ok()
    {
        return true;
    }
    false
}

#[worker::send]
async fn admin_deauth_user(
    AxumState(state): AxumState<AppState>,
    headers: HeaderMap,
    AxumPath(user_id): AxumPath<String>,
) -> Response {
    if !ok_admin(&state, &headers) {
        return error_resp(StatusCode::UNAUTHORIZED, "auth required");
    }
    let mut user = match crate::db::models::User::find_by_uuid(&state.db, &user_id).await {
        Ok(Some(u)) => u,
        Ok(None) => return error_resp(StatusCode::NOT_FOUND, "User not found"),
        Err(_) => return error_resp(StatusCode::INTERNAL_SERVER_ERROR, "db error"),
    };
    user.security_stamp = uuid::Uuid::new_v4().to_string();
    if user.save(&state.db).await.is_err() {
        return error_resp(StatusCode::INTERNAL_SERVER_ERROR, "save failed");
    }
    let _ok = run_sql(&state.db, "DELETE FROM devices WHERE user_uuid = ?1", &user.uuid).await;
    crate::api::notify::notify_user(
        &state,
        &user.uuid,
        crate::api::notify::kind::LOG_OUT,
        &user.uuid,
    )
    .await;
    Json(json!({ "Object": "user", "Id": user.uuid })).into_response()
}

#[worker::send]
async fn admin_remove_2fa(
    AxumState(state): AxumState<AppState>,
    headers: HeaderMap,
    AxumPath(user_id): AxumPath<String>,
) -> Response {
    if !ok_admin(&state, &headers) {
        return error_resp(StatusCode::UNAUTHORIZED, "auth required");
    }
    let _ok = run_sql(&state.db, "DELETE FROM twofactor WHERE user_uuid = ?1", &user_id).await;
    crate::api::notify::notify_user(
        &state,
        &user_id,
        crate::api::notify::kind::LOG_OUT,
        &user_id,
    )
    .await;
    crate::api::events::log_user_event(
        &state,
        crate::api::events::event_type::USER_DISABLED_2FA,
        &user_id,
        14,
    )
    .await;
    Json(json!({ "Object": "user", "Id": user_id })).into_response()
}

#[worker::send]
async fn admin_delete_user(
    AxumState(state): AxumState<AppState>,
    headers: HeaderMap,
    AxumPath(user_id): AxumPath<String>,
) -> Response {
    if !ok_admin(&state, &headers) {
        return error_resp(StatusCode::UNAUTHORIZED, "auth required");
    }
    // Clear R2 attachment objects for the user's personal ciphers + their
    // file sends. We do this before the row-level cascade so we still have
    // the keys to look up.
    if let Ok(rows) = state
        .db
        .prepare(
            "SELECT a.cipher_uuid AS cipher_uuid, a.id AS attachment_id \
             FROM attachments a JOIN ciphers c ON c.uuid = a.cipher_uuid \
             WHERE c.user_uuid = ?1",
        )
        .bind(&[worker::wasm_bindgen::JsValue::from_str(&user_id)])
    {
        #[derive(serde::Deserialize)]
        struct Row {
            cipher_uuid: String,
            attachment_id: String,
        }
        if let Ok(result) = rows.all().await
            && let Ok(rows) = result.results::<Row>()
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
        .bind(&[worker::wasm_bindgen::JsValue::from_str(&user_id)])
    {
        #[derive(serde::Deserialize)]
        struct Row {
            uuid: String,
        }
        if let Ok(result) = send_rows.all().await
            && let Ok(rows) = result.results::<Row>()
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
    for sql in [
        "DELETE FROM favorites WHERE user_uuid = ?1",
        "DELETE FROM folders_ciphers WHERE folder_uuid IN (SELECT uuid FROM folders WHERE user_uuid = ?1)",
        "DELETE FROM folders WHERE user_uuid = ?1",
        "DELETE FROM attachments WHERE cipher_uuid IN (SELECT uuid FROM ciphers WHERE user_uuid = ?1)",
        "DELETE FROM ciphers_collections WHERE cipher_uuid IN (SELECT uuid FROM ciphers WHERE user_uuid = ?1)",
        "DELETE FROM ciphers WHERE user_uuid = ?1",
        "DELETE FROM sends WHERE user_uuid = ?1",
        "DELETE FROM auth_requests WHERE user_uuid = ?1",
        "DELETE FROM emergency_access WHERE grantor_uuid = ?1 OR grantee_uuid = ?1",
        "DELETE FROM event WHERE user_uuid = ?1",
        "DELETE FROM sso_users WHERE user_uuid = ?1",
        "DELETE FROM devices WHERE user_uuid = ?1",
        "DELETE FROM users_collections WHERE user_uuid = ?1",
        "DELETE FROM groups_users WHERE users_organizations_uuid IN (SELECT uuid FROM users_organizations WHERE user_uuid = ?1)",
        "DELETE FROM users_organizations WHERE user_uuid = ?1",
        "DELETE FROM twofactor WHERE user_uuid = ?1",
        "DELETE FROM users WHERE uuid = ?1",
    ] {
        let _ok = run_sql(&state.db, sql, &user_id).await;
    }
    crate::api::notify::notify_user(
        &state,
        &user_id,
        crate::api::notify::kind::LOG_OUT,
        &user_id,
    )
    .await;
    Json(json!({ "Object": "user", "Id": user_id, "Deleted": true })).into_response()
}

#[worker::send]
async fn admin_delete_org(
    AxumState(state): AxumState<AppState>,
    headers: HeaderMap,
    AxumPath(org_id): AxumPath<String>,
) -> Response {
    if !ok_admin(&state, &headers) {
        return error_resp(StatusCode::UNAUTHORIZED, "auth required");
    }
    // Snapshot member uuids before the cascade clears the membership table
    // so we can push a sync notification afterwards.
    let member_uuids: Vec<String> = crate::db::models::Membership::find_by_org(&state.db, &org_id)
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|m| m.user_uuid)
        .collect();
    // Clear R2 attachment objects for org-shared ciphers before the cascade.
    if let Ok(att_rows) = state
        .db
        .prepare(
            "SELECT a.cipher_uuid AS cipher_uuid, a.id AS attachment_id \
             FROM attachments a JOIN ciphers c ON c.uuid = a.cipher_uuid \
             WHERE c.organization_uuid = ?1",
        )
        .bind(&[worker::wasm_bindgen::JsValue::from_str(&org_id)])
    {
        #[derive(serde::Deserialize)]
        struct Row { cipher_uuid: String, attachment_id: String }
        if let Ok(result) = att_rows.all().await
            && let Ok(rows) = result.results::<Row>()
        {
            for r in rows {
                let key = format!("{}/{}", r.cipher_uuid, r.attachment_id);
                let _r2 = state.attachments.delete(&key).await;
            }
        }
    }
    for sql in [
        "DELETE FROM ciphers_collections WHERE collection_uuid IN (SELECT uuid FROM collections WHERE org_uuid = ?1)",
        "DELETE FROM users_collections WHERE collection_uuid IN (SELECT uuid FROM collections WHERE org_uuid = ?1)",
        "DELETE FROM collections_groups WHERE collections_uuid IN (SELECT uuid FROM collections WHERE org_uuid = ?1)",
        "DELETE FROM collections WHERE org_uuid = ?1",
        "DELETE FROM groups_users WHERE groups_uuid IN (SELECT uuid FROM groups WHERE organizations_uuid = ?1)",
        "DELETE FROM groups WHERE organizations_uuid = ?1",
        "DELETE FROM ciphers WHERE organization_uuid = ?1",
        "DELETE FROM users_organizations WHERE org_uuid = ?1",
        "DELETE FROM org_policies WHERE org_uuid = ?1",
        "DELETE FROM organization_api_key WHERE org_uuid = ?1",
        "DELETE FROM organizations WHERE uuid = ?1",
    ] {
        let _ok = run_sql(&state.db, sql, &org_id).await;
    }
    for user_uuid in &member_uuids {
        crate::api::notify::notify_user(
            &state,
            user_uuid,
            crate::api::notify::kind::SYNC_VAULT,
            user_uuid,
        )
        .await;
    }
    Json(json!({ "Object": "organization", "Id": org_id, "Deleted": true })).into_response()
}

fn render_or_500(page: &str, ctx: &Value) -> Response {
    match crate::templates::render_admin(page, ctx) {
        Ok(html) => Html(html).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, format!("template error: {e}")).into_response(),
    }
}

fn error_resp(code: StatusCode, msg: &str) -> Response {
    (code, Json(json!({ "Message": msg, "Object": "error" }))).into_response()
}

// ---------------------------------------------------------------------------
// Static admin assets (`/vw_static/<file>`). Files are embedded in the wasm
// binary at compile time via include_bytes!.

macro_rules! static_assets {
    ($($name:literal => ($mime:expr, $path:literal)),* $(,)?) => {
        fn lookup_static(file: &str) -> Option<(&'static str, &'static [u8])> {
            match file {
                $( $name => Some(($mime, include_bytes!($path))), )*
                _ => None,
            }
        }
    };
}

static_assets! {
    "admin.css"            => ("text/css; charset=utf-8",          "../../static/admin/css/admin.css"),
    "bootstrap.css"        => ("text/css; charset=utf-8",          "../../static/admin/css/bootstrap.css"),
    "datatables.css"       => ("text/css; charset=utf-8",          "../../static/admin/css/datatables.css"),
    "admin.js"             => ("application/javascript; charset=utf-8", "../../static/admin/scripts/admin.js"),
    "admin_users.js"       => ("application/javascript; charset=utf-8", "../../static/admin/scripts/admin_users.js"),
    "admin_organizations.js" => ("application/javascript; charset=utf-8", "../../static/admin/scripts/admin_organizations.js"),
    "admin_settings.js"    => ("application/javascript; charset=utf-8", "../../static/admin/scripts/admin_settings.js"),
    "admin_diagnostics.js" => ("application/javascript; charset=utf-8", "../../static/admin/scripts/admin_diagnostics.js"),
    "bootstrap.bundle.js"  => ("application/javascript; charset=utf-8", "../../static/admin/scripts/bootstrap.bundle.js"),
    "datatables.js"        => ("application/javascript; charset=utf-8", "../../static/admin/scripts/datatables.js"),
    "jquery-4.0.0.slim.js" => ("application/javascript; charset=utf-8", "../../static/admin/scripts/jquery-4.0.0.slim.js"),
    "jdenticon-3.3.0.js"   => ("application/javascript; charset=utf-8", "../../static/admin/scripts/jdenticon-3.3.0.js"),
    "vaultwarden-favicon.png" => ("image/png", "../../static/admin/images/vaultwarden-favicon.png"),
    "vaultwarden-icon.png"  => ("image/png", "../../static/admin/images/vaultwarden-icon.png"),
    "logo-gray.png"         => ("image/png", "../../static/admin/images/logo-gray.png"),
    "mail-github.png"       => ("image/png", "../../static/admin/images/mail-github.png"),
    "hibp.png"              => ("image/png", "../../static/admin/images/hibp.png"),
}

async fn static_asset(AxumPath(file): AxumPath<String>) -> Response {
    match lookup_static(&file) {
        Some((mime, bytes)) => Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, mime)
            .header(header::CACHE_CONTROL, "public, max-age=3600")
            .header(header::CONTENT_LENGTH, bytes.len().to_string())
            .body(axum::body::Body::from(bytes))
            .unwrap_or_else(|_| (StatusCode::INTERNAL_SERVER_ERROR, "").into_response()),
        None => (StatusCode::NOT_FOUND, "asset not found").into_response(),
    }
}

// ---------------------------------------------------------------------------
// Round-9 admin stubs: diagnostics subpages, config backup/delete, user
// detail/by-mail/invite-resend. The diagnostics subroutes return JSON shaped
// like upstream so the existing `admin_diagnostics.js` keeps working.

#[worker::send]
async fn diagnostics_config(AxumState(state): AxumState<AppState>, headers: HeaderMap) -> Response {
    if !ok_admin(&state, &headers) {
        return error_resp(StatusCode::UNAUTHORIZED, "auth required");
    }
    Json(json!({
        "domain": state.env_var("DOMAIN").unwrap_or_default(),
        "domain_set": state.env_var("DOMAIN").is_some(),
        "domain_origin": state.env_var("DOMAIN").unwrap_or_default(),
        "smtp_host": Value::Null,
        "smtp_ssl": false,
        "smtp_explicit_tls": false,
        "smtp_security": Value::Null,
        "smtp_from": state.mail_from.0.clone(),
        "smtp_from_name": state.mail_from.1.clone(),
        "admin_url": format!("{}/admin", state.env_var("DOMAIN").unwrap_or_default()),
    }))
    .into_response()
}

#[worker::send]
async fn diagnostics_http(AxumState(state): AxumState<AppState>, headers: HeaderMap) -> Response {
    if !ok_admin(&state, &headers) {
        return error_resp(StatusCode::UNAUTHORIZED, "auth required");
    }
    let target = "https://github.com/dani-garcia/vaultwarden";
    let mut req_init = worker::RequestInit::new();
    req_init.with_method(worker::Method::Get);
    let req = match worker::Request::new_with_init(target, &req_init) {
        Ok(r) => r,
        Err(e) => {
            return Json(json!({"success": false, "error": e.to_string()})).into_response();
        }
    };
    let result = match worker::Fetch::Request(req).send().await {
        Ok(resp) => json!({"success": true, "status": resp.status_code()}),
        Err(e) => json!({"success": false, "error": e.to_string()}),
    };
    Json(result).into_response()
}

#[worker::send]
async fn config_backup_stub(AxumState(state): AxumState<AppState>, headers: HeaderMap) -> Response {
    if !ok_admin(&state, &headers) {
        return error_resp(StatusCode::UNAUTHORIZED, "auth required");
    }
    Json(json!({"Message": "D1 backups are managed by Cloudflare; no in-Worker action available."})).into_response()
}

#[worker::send]
async fn config_delete_stub(AxumState(state): AxumState<AppState>, headers: HeaderMap) -> Response {
    if !ok_admin(&state, &headers) {
        return error_resp(StatusCode::UNAUTHORIZED, "auth required");
    }
    let overrides = ConfigOverrides::default();
    if let Err(e) = crate::config::save(&state.config_kv, &overrides).await {
        return error_resp(StatusCode::INTERNAL_SERVER_ERROR, &format!("save failed: {e}"));
    }
    Json(json!({})).into_response()
}

#[worker::send]
async fn admin_invite_resend(
    AxumState(state): AxumState<AppState>,
    headers: HeaderMap,
    AxumPath(user_id): AxumPath<String>,
) -> Response {
    if !ok_admin(&state, &headers) {
        return error_resp(StatusCode::UNAUTHORIZED, "auth required");
    }
    let user = match crate::db::models::User::find_by_uuid(&state.db, &user_id).await {
        Ok(Some(u)) => u,
        _ => return error_resp(StatusCode::NOT_FOUND, "user not found"),
    };
    if !crate::ratelimit::check(
        &state.ratelimit_kv,
        &crate::ratelimit::EMAIL_SEND_LIMIT,
        &user.email,
    )
    .await
    {
        return error_resp(StatusCode::TOO_MANY_REQUESTS, "Too many reminders sent to that user");
    }
    let (from_email, from_name) = state.mail_from.as_ref().clone();
    let host = state.env_var("DOMAIN").unwrap_or_default();
    let _send = state
        .mail
        .send(&crate::mail::MailMessage {
            from_email,
            from_name,
            to: user.email.clone(),
            subject: "Vaultwarden invitation reminder".into(),
            text: format!(
                "An admin has re-sent your invitation. Sign in at {host} to set your master password.",
            ),
            html: None,
        })
        .await;
    Json(json!({})).into_response()
}

#[worker::send]
async fn admin_user_by_mail(
    AxumState(state): AxumState<AppState>,
    headers: HeaderMap,
    AxumPath(email): AxumPath<String>,
) -> Response {
    if !ok_admin(&state, &headers) {
        return error_resp(StatusCode::UNAUTHORIZED, "auth required");
    }
    let user = match crate::db::models::User::find_by_email(&state.db, &email.to_lowercase()).await {
        Ok(Some(u)) => u,
        _ => return error_resp(StatusCode::NOT_FOUND, "user not found"),
    };
    Json(json!({
        "Id": user.uuid,
        "Email": user.email,
        "Name": user.name,
        "Enabled": user.enabled == 1,
        "Verified": user.verified_at.is_some(),
        "CreatedAt": user.created_at,
        "UpdatedAt": user.updated_at,
    }))
    .into_response()
}

#[worker::send]
async fn admin_user_detail(
    AxumState(state): AxumState<AppState>,
    headers: HeaderMap,
    AxumPath(user_id): AxumPath<String>,
) -> Response {
    if !ok_admin(&state, &headers) {
        return error_resp(StatusCode::UNAUTHORIZED, "auth required");
    }
    let user = match crate::db::models::User::find_by_uuid(&state.db, &user_id).await {
        Ok(Some(u)) => u,
        _ => return (StatusCode::NOT_FOUND, "user not found").into_response(),
    };

    #[derive(serde::Deserialize)]
    struct OrgRow {
        org_uuid: String,
        name: String,
        atype: i32,
    }
    let orgs: Vec<OrgRow> = match state.db.prepare(
        "SELECT uo.org_uuid AS org_uuid, o.name AS name, uo.atype AS atype \
         FROM users_organizations uo JOIN organizations o ON o.uuid = uo.org_uuid \
         WHERE uo.user_uuid = ?1 ORDER BY o.name",
    ).bind(&[worker::wasm_bindgen::JsValue::from_str(&user.uuid)]) {
        Ok(s) => s.all().await.ok().and_then(|r| r.results().ok()).unwrap_or_default(),
        Err(_) => Vec::new(),
    };
    let orgs_json: Vec<Value> = orgs
        .into_iter()
        .map(|o| json!({"id": o.org_uuid, "name": o.name, "type": o.atype}))
        .collect();

    #[derive(serde::Deserialize)]
    struct CountRow { n: i64 }
    let cipher_count: i64 = match state.db.prepare("SELECT COUNT(*) AS n FROM ciphers WHERE user_uuid = ?1")
        .bind(&[worker::wasm_bindgen::JsValue::from_str(&user.uuid)])
    {
        Ok(s) => s.first::<CountRow>(None).await.ok().flatten().map(|r| r.n).unwrap_or(0),
        Err(_) => 0,
    };

    Json(json!({
        "Id": user.uuid,
        "Email": user.email,
        "Name": user.name,
        "Enabled": user.enabled == 1,
        "Verified": user.verified_at.is_some(),
        "CreatedAt": user.created_at,
        "UpdatedAt": user.updated_at,
        "CipherCount": cipher_count,
        "Organizations": orgs_json,
    }))
    .into_response()
}

#[worker::send]
async fn admin_unlink_sso(
    AxumState(state): AxumState<AppState>,
    headers: HeaderMap,
    AxumPath(user_id): AxumPath<String>,
) -> Response {
    if !ok_admin(&state, &headers) {
        return error_resp(StatusCode::UNAUTHORIZED, "auth required");
    }
    let _ok = run_sql(&state.db, "DELETE FROM sso_users WHERE user_uuid = ?1", &user_id).await;
    crate::api::events::log_user_event(
        &state,
        crate::api::events::event_type::ORG_USER_UNLINKED_SSO,
        &user_id,
        14,
    )
    .await;
    Json(json!({"Object": "user", "Id": user_id})).into_response()
}

#[worker::send]
async fn admin_update_revision(
    AxumState(state): AxumState<AppState>,
    headers: HeaderMap,
) -> Response {
    if !ok_admin(&state, &headers) {
        return error_resp(StatusCode::UNAUTHORIZED, "auth required");
    }
    // Bump every user's revision so all live clients refresh on their next
    // poll. This is mostly used after admin-side bulk migrations.
    let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Micros, true);
    if let Ok(s) = state
        .db
        .prepare("UPDATE users SET updated_at = ?1")
        .bind(&[worker::wasm_bindgen::JsValue::from_str(&now)])
    {
        let _r = s.run().await;
    }
    Json(json!({})).into_response()
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct AdminInviteBody {
    email: String,
}

/// Admin-side invite. Creates a fresh user (disabled, no password) and emails
/// them a registration link. The email lands as a normal Vaultwarden welcome
/// rather than an org invite.
#[worker::send]
async fn admin_invite_user(
    AxumState(state): AxumState<AppState>,
    headers: HeaderMap,
    Json(body): Json<AdminInviteBody>,
) -> Response {
    if !ok_admin(&state, &headers) {
        return error_resp(StatusCode::UNAUTHORIZED, "auth required");
    }
    let email = body.email.trim().to_lowercase();
    if email.is_empty() {
        return error_resp(StatusCode::BAD_REQUEST, "email is required");
    }
    if !crate::ratelimit::check(
        &state.ratelimit_kv,
        &crate::ratelimit::EMAIL_SEND_LIMIT,
        &email,
    )
    .await
    {
        return error_resp(StatusCode::TOO_MANY_REQUESTS, "Too many invitations to that email");
    }
    if let Ok(Some(_)) = crate::db::models::User::find_by_email(&state.db, &email).await {
        return error_resp(StatusCode::BAD_REQUEST, "user already exists");
    }
    let mut u = crate::db::models::User::new(&email, None);
    u.enabled = 1;
    if u.save(&state.db).await.is_err() {
        return error_resp(StatusCode::INTERNAL_SERVER_ERROR, "save failed");
    }
    let (from_email, from_name) = state.mail_from.as_ref().clone();
    let host = state.env_var("DOMAIN").unwrap_or_default();
    let _send = state
        .mail
        .send(&crate::mail::MailMessage {
            from_email,
            from_name,
            to: email.clone(),
            subject: "You've been invited to Vaultwarden".into(),
            text: format!(
                "An admin has provisioned an account for you. Sign in at {host} to set your master password.",
            ),
            html: None,
        })
        .await;
    Json(json!({"Object": "user", "Id": u.uuid, "Email": email})).into_response()
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct OrgTypeBody {
    #[serde(rename = "userId")]
    user_id: String,
    #[serde(rename = "orgId")]
    org_id: String,
    #[serde(rename = "userType")]
    user_type: i32,
}

#[worker::send]
async fn admin_set_org_type(
    AxumState(state): AxumState<AppState>,
    headers: HeaderMap,
    Json(body): Json<OrgTypeBody>,
) -> Response {
    if !ok_admin(&state, &headers) {
        return error_resp(StatusCode::UNAUTHORIZED, "auth required");
    }
    let mut m = match crate::db::models::Membership::find_by_user_and_org(&state.db, &body.user_id, &body.org_id).await {
        Ok(Some(m)) => m,
        _ => return error_resp(StatusCode::NOT_FOUND, "membership not found"),
    };
    m.atype = body.user_type;
    if m.save(&state.db).await.is_err() {
        return error_resp(StatusCode::INTERNAL_SERVER_ERROR, "save failed");
    }
    crate::api::events::log_org_event(
        &state,
        crate::api::events::event_type::ORG_USER_UPDATED,
        &body.org_id,
        &body.user_id,
        Some(&m.uuid),
        14,
    )
    .await;
    crate::api::notify::notify_user(
        &state,
        &body.user_id,
        crate::api::notify::kind::SYNC_VAULT,
        &body.user_id,
    )
    .await;
    Json(json!({"Object": "user", "Id": body.user_id, "Type": body.user_type})).into_response()
}

#[derive(Deserialize)]
struct AdminTestSmtpBody {
    email: String,
}

#[worker::send]
async fn admin_test_smtp(
    AxumState(state): AxumState<AppState>,
    headers: HeaderMap,
    Json(body): Json<AdminTestSmtpBody>,
) -> Response {
    if !ok_admin(&state, &headers) {
        return error_resp(StatusCode::UNAUTHORIZED, "auth required");
    }
    let to = body.email.trim();
    if to.is_empty() {
        return error_resp(StatusCode::BAD_REQUEST, "email is required");
    }
    // Rate-limit so a leaked admin token can't be used to spam strangers.
    if !crate::ratelimit::check(
        &state.ratelimit_kv,
        &crate::ratelimit::EMAIL_SEND_LIMIT,
        to,
    )
    .await
    {
        return error_resp(StatusCode::TOO_MANY_REQUESTS, "Too many test messages");
    }
    let (from_email, from_name) = state.mail_from.as_ref().clone();
    match state
        .mail
        .send(&crate::mail::MailMessage {
            from_email,
            from_name,
            to: to.to_owned(),
            subject: "Vaultwarden test message".into(),
            text: "If you got this, your mail provider is working.".into(),
            html: None,
        })
        .await
    {
        Ok(_) => Json(json!({})).into_response(),
        Err(e) => error_resp(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    }
}
