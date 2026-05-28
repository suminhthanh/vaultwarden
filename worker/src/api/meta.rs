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
use crate::db::models::{Device, User};

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/config", get(get_config))
        .route("/api/devices", get(list_devices))
        .route("/api/accounts/security-stamp", post(rotate_security_stamp))
        .route("/api/accounts/keys", post(set_account_keys))
        // Stubs that mirror upstream's empty-list / no-op shape so clients
        // don't error on optional features we don't implement.
        .route("/api/hibp/breach", get(hibp_breach))
        .route("/api/plans", get(plans_list))
        .route("/api/settings/domains", get(settings_domains).post(settings_domains_save).put(settings_domains_save))
        .route("/api/sso/prevalidate", get(sso_prevalidate))
        .route("/api/connect/oidc-signin", post(oidc_signin_stub))
        .route("/api/connect/authorize", get(oidc_signin_stub))
        .route("/api/anonymous-hub", get(anonymous_hub_stub))
        .route("/api/hub", get(anonymous_hub_stub))
        .route("/api/tasks", get(tasks_stub))
        .route("/api/app-id.json", get(app_id_json))
        .route("/api/test/smtp", post(test_smtp))
        .route("/api/public/organization/import", post(public_org_import))
        .route("/api/accounts/key-management/rotate-user-account-keys", post(rotate_user_account_keys))
        .route("/.well-known/apple-app-site-association", get(apple_app_site_association))
        .route("/api/webauthn", get(global_webauthn_config))
        .route("/api/organizations/overview", get(admin_org_overview_alias))
        .route(
            "/api/organizations/00000000-01DC-01DC-01DC-000000000000/policies/master-password",
            get(default_master_password_policy),
        )
}

async fn get_config(AxumState(state): AxumState<AppState>) -> Json<Value> {
    let domain = state
        .env_var("DOMAIN")
        .unwrap_or_else(|| "http://localhost".to_owned());
    Json(json!({
        "version": "2025.12.0",
        "gitHash": Value::Null,
        "server": { "name": "Vaultwarden", "url": "https://github.com/dani-garcia/vaultwarden" },
        "settings": { "disableUserRegistration": false },
        "environment": {
            "vault": domain,
            "api": format!("{domain}/api"),
            "identity": format!("{domain}/identity"),
            "notifications": format!("{domain}/notifications"),
            "sso": "",
            "cloudRegion": Value::Null,
        },
        "push": { "pushTechnology": 0, "vapidPublicKey": Value::Null },
        "featureStates": {},
        "object": "config",
    }))
}

#[worker::send]
async fn list_devices(
    AxumState(state): AxumState<AppState>,
    headers: Headers,
) -> impl IntoResponse {
    let devices = match Device::find_by_user(&state.db, &headers.user.uuid).await {
        Ok(d) => d,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "Message": "database error" })),
            )
        }
    };
    let data: Vec<Value> = devices
        .iter()
        .map(|d| {
            json!({
                "Object": "device",
                "Id": d.uuid,
                "Name": d.name,
                "Type": d.atype,
                "CreationDate": d.created_at,
                "RevisionDate": d.updated_at,
            })
        })
        .collect();
    (StatusCode::OK, Json(json!({ "Object": "list", "Data": data, "ContinuationToken": Value::Null })))
}

#[worker::send]
async fn rotate_security_stamp(
    AxumState(state): AxumState<AppState>,
    headers: Headers,
) -> impl IntoResponse {
    let mut user = headers.user;
    user.security_stamp = uuid::Uuid::new_v4().to_string();
    if user.save(&state.db).await.is_err() {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "Message": "save failed" })));
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
        crate::api::events::event_type::USER_CHANGED_PASSWORD,
        &user.uuid,
        headers.device.atype,
    )
    .await;
    (StatusCode::OK, Json(json!({})))
}

#[derive(Deserialize)]
struct KeysData {
    #[serde(rename = "publicKey")]
    public_key: String,
    #[serde(rename = "encryptedPrivateKey")]
    encrypted_private_key: String,
}

#[worker::send]
async fn set_account_keys(
    AxumState(state): AxumState<AppState>,
    headers: Headers,
    Json(body): Json<KeysData>,
) -> impl IntoResponse {
    let mut user: User = headers.user;
    user.public_key = Some(body.public_key);
    user.private_key = Some(body.encrypted_private_key);
    if user.save(&state.db).await.is_err() {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "Message": "save failed" })));
    }
    (
        StatusCode::OK,
        Json(json!({
            "Object": "keys",
            "PublicKey": user.public_key,
            "PrivateKey": user.private_key,
        })),
    )
}

// ---------------------------------------------------------------------------
// Public stubs.

#[derive(Deserialize)]
#[allow(dead_code)]
struct HibpQuery {
    #[serde(default)]
    username: Option<String>,
}

#[worker::send]
async fn hibp_breach(
    AxumState(state): AxumState<AppState>,
    axum::extract::Query(q): axum::extract::Query<HibpQuery>,
) -> impl IntoResponse {
    // If HIBP_API_KEY is configured, forward to the real HIBP API. Otherwise
    // return an empty list — the password-health view treats "no breaches"
    // identically to "API not wired", so this stays clean for self-hosters
    // without an HIBP subscription.
    let username = match q.username.as_deref().filter(|s| !s.is_empty()) {
        Some(u) => u.to_owned(),
        None => return (StatusCode::OK, Json(json!([]))),
    };
    let api_key = match state.env_var("HIBP_API_KEY") {
        Some(k) if !k.is_empty() => k,
        _ => return (StatusCode::OK, Json(json!([]))),
    };
    let encoded = username
        .bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                String::from_utf8(vec![b]).unwrap_or_default()
            }
            _ => format!("%{:02X}", b),
        })
        .collect::<String>();
    let url = format!(
        "https://haveibeenpwned.com/api/v3/breachedaccount/{encoded}?truncateResponse=false"
    );
    let hdrs = worker::Headers::new();
    let _h1 = hdrs.set("hibp-api-key", &api_key);
    let _h2 = hdrs.set("user-agent", "vaultwarden-worker");
    let mut init = worker::RequestInit::new();
    init.with_method(worker::Method::Get).with_headers(hdrs);
    let req = match worker::Request::new_with_init(&url, &init) {
        Ok(r) => r,
        Err(_) => return (StatusCode::OK, Json(json!([]))),
    };
    let mut resp = match worker::Fetch::Request(req).send().await {
        Ok(r) => r,
        Err(_) => return (StatusCode::OK, Json(json!([]))),
    };
    let status = resp.status_code();
    if status == 404 || !(200..=299).contains(&status) {
        return (StatusCode::OK, Json(json!([])));
    }
    let parsed: Value = resp.json::<Value>().await.unwrap_or_else(|_| json!([]));
    (StatusCode::OK, Json(parsed))
}

async fn plans_list() -> impl IntoResponse {
    (
        StatusCode::OK,
        Json(json!({
            "Object": "list",
            "Data": [],
            "ContinuationToken": Value::Null,
        })),
    )
}

#[worker::send]
async fn settings_domains(headers: Headers) -> impl IntoResponse {
    let equivalent: Value = serde_json::from_str(&headers.user.equivalent_domains).unwrap_or(json!([]));
    let excluded: Value = serde_json::from_str(&headers.user.excluded_globals).unwrap_or(json!([]));
    (
        StatusCode::OK,
        Json(json!({
            "Object": "domains",
            "EquivalentDomains": equivalent,
            "GlobalEquivalentDomains": [],
            "ExcludedGlobalEquivalentDomains": excluded,
        })),
    )
}

#[derive(Deserialize)]
struct DomainsBody {
    #[serde(default, alias = "EquivalentDomains")]
    equivalent_domains: Option<Value>,
    #[serde(default, alias = "ExcludedGlobalEquivalentDomains")]
    excluded_global_equivalent_domains: Option<Value>,
}

#[worker::send]
async fn settings_domains_save(
    AxumState(state): AxumState<AppState>,
    headers: Headers,
    Json(body): Json<DomainsBody>,
) -> impl IntoResponse {
    let mut user = headers.user;
    if let Some(eq) = body.equivalent_domains {
        user.equivalent_domains = eq.to_string();
    }
    if let Some(excl) = body.excluded_global_equivalent_domains {
        user.excluded_globals = excl.to_string();
    }
    if user.save(&state.db).await.is_err() {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"Message": "save failed"})),
        );
    }
    let equivalent: Value = serde_json::from_str(&user.equivalent_domains).unwrap_or(json!([]));
    let excluded: Value = serde_json::from_str(&user.excluded_globals).unwrap_or(json!([]));
    (
        StatusCode::OK,
        Json(json!({
            "Object": "domains",
            "EquivalentDomains": equivalent,
            "GlobalEquivalentDomains": [],
            "ExcludedGlobalEquivalentDomains": excluded,
        })),
    )
}

async fn sso_prevalidate() -> impl IntoResponse {
    (StatusCode::NOT_IMPLEMENTED, Json(json!({"Message": "SSO is not configured"})))
}

async fn oidc_signin_stub() -> impl IntoResponse {
    (StatusCode::NOT_IMPLEMENTED, Json(json!({"Message": "OIDC sign-in is not configured"})))
}

async fn anonymous_hub_stub() -> impl IntoResponse {
    (StatusCode::NOT_IMPLEMENTED, Json(json!({"Message": "anonymous hub uses WebSocket; connect via /notifications/anonymous-hub"})))
}

async fn tasks_stub() -> impl IntoResponse {
    (StatusCode::OK, Json(json!({"Object": "list", "Data": [], "ContinuationToken": Value::Null})))
}

async fn app_id_json() -> impl IntoResponse {
    // FIDO U2F app-id JSON shape. Unused by passkey clients but mobile/web
    // still poll it.
    (
        StatusCode::OK,
        Json(json!({
            "trustedFacets": [{
                "version": {"major": 1, "minor": 0},
                "ids": [],
            }],
        })),
    )
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct TestSmtpBody {
    email: Option<String>,
}

#[worker::send]
async fn test_smtp(
    AxumState(state): AxumState<AppState>,
    Json(body): Json<TestSmtpBody>,
) -> impl IntoResponse {
    let to = body.email.unwrap_or_else(|| "test@example.com".to_owned());
    let (from_email, from_name) = state.mail_from.as_ref().clone();
    match state
        .mail
        .send(&crate::mail::MailMessage {
            from_email,
            from_name,
            to,
            subject: "Vaultwarden test message".into(),
            text: "If you received this, your mail provider is working.".into(),
            html: None,
        })
        .await
    {
        Ok(_) => (StatusCode::OK, Json(Value::Null)),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"Message": e.to_string()})),
        ),
    }
}

/// Auth model for `/api/public/...`: the directory connector authenticates
/// with `Authorization: Bearer <token>`, where the token was minted by the
/// org API-key endpoint (persisted in `organization_api_key`). We resolve
/// the org by matching the token against any stored org API key.
async fn require_public_org(
    state: &AppState,
    headers: &axum::http::HeaderMap,
) -> Result<String, (StatusCode, Json<Value>)> {
    use subtle::ConstantTimeEq;
    let bearer = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer ").or_else(|| v.strip_prefix("bearer ")))
        .map(str::to_owned);
    let Some(token) = bearer else {
        return Err((StatusCode::UNAUTHORIZED, Json(json!({"Message": "missing Bearer token"}))));
    };
    if token.is_empty() {
        return Err((StatusCode::UNAUTHORIZED, Json(json!({"Message": "empty token"}))));
    }
    // Look up by scanning all keys — D1 has no full-table secondary index API
    // here, but org API keys are rare so this is acceptable.
    #[derive(serde::Deserialize)]
    struct Row { org_uuid: String, api_key: String }
    let stmt = match state
        .db
        .prepare("SELECT org_uuid, api_key FROM organization_api_key WHERE atype = 0")
        .bind(&[])
    {
        Ok(s) => s,
        Err(_) => {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"Message": "db error"})),
            ));
        }
    };
    let rows: Vec<Row> = stmt.all().await.ok().and_then(|r| r.results::<Row>().ok()).unwrap_or_default();
    for r in rows {
        if bool::from(r.api_key.as_bytes().ct_eq(token.as_bytes())) {
            return Ok(r.org_uuid);
        }
    }
    Err((StatusCode::UNAUTHORIZED, Json(json!({"Message": "invalid org token"}))))
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct PublicImportBody {
    #[serde(default)]
    members: Vec<PublicImportMember>,
    #[serde(default)]
    groups: Vec<PublicImportGroup>,
    #[serde(default, rename = "overwriteExisting")]
    overwrite_existing: Option<bool>,
}

#[derive(Deserialize)]
struct PublicImportMember {
    email: String,
    #[serde(default, rename = "externalId")]
    external_id: Option<String>,
    #[serde(default)]
    deleted: bool,
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct PublicImportGroup {
    name: String,
    #[serde(default, rename = "externalId")]
    external_id: Option<String>,
    #[serde(default, rename = "memberExternalIds")]
    member_external_ids: Vec<String>,
    #[serde(default)]
    deleted: bool,
}

#[worker::send]
async fn public_org_import(
    AxumState(state): AxumState<AppState>,
    headers: axum::http::HeaderMap,
    Json(body): Json<PublicImportBody>,
) -> impl IntoResponse {
    use crate::db::models::{Membership, Organization, User};

    let org_id = match require_public_org(&state, &headers).await {
        Ok(id) => id,
        Err(e) => return e,
    };

    let mut invited = 0u32;
    let mut removed = 0u32;

    for member in body.members {
        let email = member.email.trim().to_lowercase();
        if email.is_empty() {
            continue;
        }
        if member.deleted {
            // Find existing membership and drop it.
            if let Ok(Some(user)) = User::find_by_email(&state.db, &email).await
                && let Ok(Some(m)) =
                    Membership::find_by_user_and_org(&state.db, &user.uuid, &org_id).await
                && m.delete(&state.db).await.is_ok()
            {
                removed += 1;
            }
            continue;
        }

        // Find or create the invitee user, mirror upstream's invited flow.
        let invitee = match User::find_by_email(&state.db, &email).await {
            Ok(Some(u)) => u,
            _ => {
                let mut u = User::new(&email, None);
                u.enabled = 1;
                u.external_id = member.external_id.clone();
                if u.save(&state.db).await.is_err() {
                    continue;
                }
                u
            }
        };
        if Membership::find_by_user_and_org(&state.db, &invitee.uuid, &org_id)
            .await
            .ok()
            .flatten()
            .is_some()
        {
            continue;
        }
        let m = Membership::new(invitee.uuid.clone(), org_id.clone(), String::new(), 2, 0);
        if m.save(&state.db).await.is_ok() {
            invited += 1;
            // Best-effort welcome / invite email.
            let (from_email, from_name) = state.mail_from.as_ref().clone();
            let host = state.env_var("DOMAIN").unwrap_or_default();
            let org_name = Organization::find_by_uuid(&state.db, &org_id)
                .await
                .ok()
                .flatten()
                .map(|o| o.name)
                .unwrap_or_else(|| "your organization".into());
            let _send = state
                .mail
                .send(&crate::mail::MailMessage {
                    from_email,
                    from_name,
                    to: email.clone(),
                    subject: format!("Join {org_name} on Vaultwarden"),
                    text: format!(
                        "You've been added to {org_name} via directory sync. Sign in at {host} to accept."
                    ),
                    html: None,
                })
                .await;
        }
    }

    state.telemetry.record(
        "public_org_import",
        &[("org", &org_id), ("invited", &invited.to_string()), ("removed", &removed.to_string())],
    );
    (
        StatusCode::OK,
        Json(json!({"Object": "publicOrganizationImport", "Invited": invited, "Removed": removed})),
    )
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct RotateAccountKeysBody {
    #[serde(default, rename = "masterPasswordHash")]
    master_password_hash: Option<String>,
    #[serde(default, rename = "key")]
    key: Option<String>,
    /// Re-wrapped public/private keypair the client sends along with the
    /// new master key. Mirrors upstream's nested keys object.
    #[serde(default)]
    keys: Option<RotateKeyPair>,
    #[serde(default, alias = "Folders")]
    folders: Option<Vec<RotateRekey>>,
    #[serde(default, alias = "Ciphers")]
    ciphers: Option<Vec<RotateRekey>>,
    #[serde(default, alias = "Sends")]
    sends: Option<Vec<RotateRekey>>,
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct RotateKeyPair {
    #[serde(rename = "publicKey")]
    public_key: String,
    #[serde(rename = "encryptedPrivateKey")]
    encrypted_private_key: String,
}

#[derive(Deserialize)]
struct RotateRekey {
    id: String,
    key: String,
}

#[worker::send]
async fn rotate_user_account_keys(
    AxumState(state): AxumState<AppState>,
    headers: Headers,
    Json(body): Json<RotateAccountKeysBody>,
) -> impl IntoResponse {
    let mut user = headers.user;
    if let Some(pw) = body.master_password_hash.as_deref()
        && !pw.is_empty()
        && !user.check_valid_password(pw)
    {
        return (StatusCode::UNAUTHORIZED, Json(json!({"Message": "Invalid password"})));
    }
    if let Some(k) = body.key {
        user.akey = k;
    }
    if let Some(kp) = body.keys {
        user.public_key = Some(kp.public_key);
        user.private_key = Some(kp.encrypted_private_key);
    }
    user.security_stamp = uuid::Uuid::new_v4().to_string();
    if user.save(&state.db).await.is_err() {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"Message": "save failed"})),
        );
    }

    // Apply per-item re-encrypted wrapping keys. Each entry is `{id, key}` —
    // the cipher/folder/send was re-encrypted client-side under the new master
    // key and we just persist the new wrapped key.
    if let Some(folders) = body.folders {
        for r in folders {
            // The body sends `{id, key}` per folder. Folder names are
            // already encrypted by the master key, so a key field has no
            // separate place to land — we just touch the row to bump its
            // revision so clients re-fetch under the new key. The PUT to
            // /api/folders/{id} carries the re-encrypted name.
            if let Ok(Some(mut f)) = crate::db::models::Folder::find_by_uuid(&state.db, &r.id).await
                && f.user_uuid == user.uuid
            {
                let _save = f.save(&state.db).await;
            }
        }
    }
    if let Some(ciphers) = body.ciphers {
        for r in ciphers {
            if let Ok(Some(mut c)) = crate::db::models::Cipher::find_by_uuid(&state.db, &r.id).await
                && c.user_uuid.as_deref() == Some(user.uuid.as_str())
            {
                c.key = Some(r.key);
                let _save = c.save(&state.db).await;
            }
        }
    }
    if let Some(sends) = body.sends {
        for r in sends {
            if let Ok(Some(mut s)) = crate::db::models::Send::find_by_uuid(&state.db, &r.id).await
                && s.user_uuid.as_deref() == Some(user.uuid.as_str())
            {
                s.akey = r.key;
                let _save = s.save(&state.db).await;
            }
        }
    }

    state.telemetry.record("account_keys_rotated", &[("user", &user.uuid)]);
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
    (StatusCode::OK, Json(Value::Null))
}

async fn global_webauthn_config() -> impl IntoResponse {
    // Bitwarden's web client polls this for global WebAuthn settings; we
    // expose nothing yet so the empty list keeps the UI happy.
    (StatusCode::OK, Json(json!({"Object": "list", "Data": [], "ContinuationToken": Value::Null})))
}

async fn admin_org_overview_alias(AxumState(_state): AxumState<AppState>) -> impl IntoResponse {
    // The actual admin org overview lives at /admin/organizations/overview;
    // upstream also exposed it at this api-prefixed path for older clients.
    (StatusCode::OK, Json(json!({"Object": "list", "Data": [], "ContinuationToken": Value::Null})))
}

async fn default_master_password_policy() -> impl IntoResponse {
    // The all-zero UUID is upstream's sentinel for "any organization" master
    // password policy. With no orgs enforcing one, return the empty default.
    (
        StatusCode::OK,
        Json(json!({
            "Object": "policy",
            "Type": 1,
            "Enabled": false,
            "Data": Value::Null,
        })),
    )
}

/// Universal Links manifest for the Bitwarden iOS app. Lets the app open
/// `/#/recover-delete?...` and similar links natively. Mirrors upstream's
/// hardcoded list of Bitwarden bundle IDs.
async fn apple_app_site_association() -> impl IntoResponse {
    (
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        Json(json!({
            "webcredentials": {
                "apps": [
                    "LTZ2PFU5D6.com.8bit.bitwarden",
                    "LTZ2PFU5D6.com.8bit.bitwarden.beta"
                ]
            }
        })),
    )
}
