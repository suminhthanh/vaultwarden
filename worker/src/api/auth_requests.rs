//! Auth requests — passwordless / "login with a known device" flow.
//!
//! Pending requesting device posts to /api/auth-requests with its
//! deviceIdentifier and accessCode (a UUID). An already-logged-in device
//! polls /api/auth-requests/pending and decides to approve or deny by
//! PUTing the encrypted user key back. When approved + within the 5 min
//! window, /identity/connect/token (with auth_request grant) lets the
//! requester finish login. We expose the request CRUD; the grant is wired
//! separately as a follow-up.

use axum::{
    Json, Router,
    extract::{Path, State as AxumState},
    http::StatusCode,
    response::IntoResponse,
    routing::get,
};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::AppState;
use crate::auth::Headers;
use crate::db::models::AuthRequest;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/auth-requests", get(list_my_requests).post(create_request))
        .route("/api/auth-requests/pending", get(list_my_requests))
        .route("/api/auth-requests/{id}", get(get_request).put(respond_request))
        .route("/api/auth-requests/{id}/response", get(get_response))
}

fn err_json(code: StatusCode, msg: &str) -> (StatusCode, Json<Value>) {
    (code, Json(json!({ "ErrorModel": { "Message": msg }, "Object": "error", "Message": msg })))
}

fn auth_request_json(r: &AuthRequest) -> Value {
    json!({
        "Object": "auth-request",
        "Id": r.uuid,
        "UserId": r.user_uuid,
        "OrganizationId": r.organization_uuid,
        "RequestDeviceIdentifier": r.request_device_identifier,
        "RequestDeviceType": r.device_type,
        "RequestIpAddress": r.request_ip,
        "ResponseDeviceId": r.response_device_id,
        "PublicKey": r.public_key,
        "Key": r.enc_key,
        "MasterPasswordHash": r.master_password_hash,
        "RequestApproved": r.approved.map(|v| v == 1),
        "CreationDate": r.creation_date,
        "ResponseDate": r.response_date,
        "AuthenticationDate": r.authentication_date,
    })
}

#[derive(Deserialize)]
struct CreateAuthRequest {
    email: String,
    #[serde(rename = "deviceIdentifier")]
    device_identifier: String,
    #[serde(rename = "accessCode")]
    access_code: String,
    #[serde(rename = "publicKey")]
    public_key: String,
    #[serde(rename = "type")]
    #[serde(default)]
    _atype: Option<i32>,
}

#[worker::send]
async fn create_request(
    AxumState(state): AxumState<AppState>,
    headers: axum::http::HeaderMap,
    Json(body): Json<CreateAuthRequest>,
) -> impl IntoResponse {
    let email = body.email.trim().to_lowercase();
    if !crate::ratelimit::check(&state.ratelimit_kv, &crate::ratelimit::REGISTER_LIMIT, &email).await {
        return err_json(StatusCode::TOO_MANY_REQUESTS, "Too many auth requests");
    }
    // Don't reveal whether the email exists. Mirror upstream: silently store a
    // request for an unknown email and let the polling client time out.
    let user_uuid = match crate::db::models::User::find_by_email(&state.db, &email).await {
        Ok(Some(u)) => u.uuid,
        _ => return (StatusCode::OK, Json(auth_request_json(&AuthRequest::new(
            String::new(),
            body.device_identifier,
            9,
            String::new(),
            body.access_code,
            body.public_key,
        )))),
    };
    let ip = headers
        .get("cf-connecting-ip")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown")
        .to_owned();
    let req = AuthRequest::new(
        user_uuid,
        body.device_identifier,
        9, // web — sensible default; the client also sends `type`
        ip,
        body.access_code,
        body.public_key,
    );
    if req.save(&state.db).await.is_err() {
        return err_json(StatusCode::INTERNAL_SERVER_ERROR, "save failed");
    }
    (StatusCode::OK, Json(auth_request_json(&req)))
}

#[worker::send]
async fn list_my_requests(
    AxumState(state): AxumState<AppState>,
    headers: Headers,
) -> impl IntoResponse {
    let rows = AuthRequest::find_by_user(&state.db, &headers.user.uuid).await.unwrap_or_default();
    let data: Vec<Value> = rows.iter().map(auth_request_json).collect();
    (StatusCode::OK, Json(json!({ "Object": "list", "Data": data, "ContinuationToken": Value::Null })))
}

#[worker::send]
async fn get_request(
    AxumState(state): AxumState<AppState>,
    headers: Headers,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let r = match AuthRequest::find_by_uuid(&state.db, &id).await {
        Ok(Some(r)) if r.user_uuid == headers.user.uuid => r,
        _ => return err_json(StatusCode::NOT_FOUND, "Auth request not found"),
    };
    (StatusCode::OK, Json(auth_request_json(&r)))
}

#[derive(Deserialize)]
struct GetResponseQuery {
    #[serde(default, rename = "code", alias = "accessCode", alias = "access_code")]
    access_code: Option<String>,
}

#[worker::send]
async fn get_response(
    AxumState(state): AxumState<AppState>,
    Path(id): Path<String>,
    axum::extract::Query(q): axum::extract::Query<GetResponseQuery>,
) -> impl IntoResponse {
    use subtle::ConstantTimeEq;
    let r = match AuthRequest::find_by_uuid(&state.db, &id).await {
        Ok(Some(r)) => r,
        _ => return err_json(StatusCode::NOT_FOUND, "Auth request not found"),
    };
    // The requesting device proves identity by knowing the access_code it
    // generated at create-time. Without that we keep the request opaque, so
    // a leaked id alone can't reveal pending login state.
    let supplied = q.access_code.as_deref().unwrap_or("");
    if !bool::from(r.access_code.as_bytes().ct_eq(supplied.as_bytes())) {
        return err_json(StatusCode::NOT_FOUND, "Auth request not found");
    }
    (StatusCode::OK, Json(auth_request_json(&r)))
}

#[derive(Deserialize)]
struct RespondBody {
    #[serde(default)]
    key: Option<String>,
    #[serde(default, rename = "masterPasswordHash")]
    master_password_hash: Option<String>,
    #[serde(rename = "deviceIdentifier")]
    _device_identifier: Option<String>,
    #[serde(rename = "requestApproved")]
    request_approved: bool,
}

#[worker::send]
async fn respond_request(
    AxumState(state): AxumState<AppState>,
    headers: Headers,
    Path(id): Path<String>,
    Json(body): Json<RespondBody>,
) -> impl IntoResponse {
    let mut r = match AuthRequest::find_by_uuid(&state.db, &id).await {
        Ok(Some(r)) if r.user_uuid == headers.user.uuid => r,
        _ => return err_json(StatusCode::NOT_FOUND, "Auth request not found"),
    };
    r.approved = Some(if body.request_approved { 1 } else { 0 });
    r.enc_key = body.key;
    r.master_password_hash = body.master_password_hash;
    r.response_device_id = Some(headers.device.uuid.clone());
    r.response_date = Some(chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Micros, true));
    if r.save(&state.db).await.is_err() {
        return err_json(StatusCode::INTERNAL_SERVER_ERROR, "save failed");
    }
    // Wake the requester's anonymous-hub WebSocket so it can finish login.
    crate::api::notify::notify_anon(&state, &r.uuid, &r.uuid).await;
    (StatusCode::OK, Json(auth_request_json(&r)))
}
