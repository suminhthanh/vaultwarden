//! Device endpoints: push token registration + lookup.
//!
//! These are the routes mobile/desktop clients call to register their FCM/APNs
//! token so the server can push sync notifications outside the WebSocket. We
//! store the token on the existing `devices.push_token` column. The actual
//! push relay (forwarding to Bitwarden's hosted push service) is wired in a
//! follow-up — for now the client is happy when we accept the token.

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
use crate::db::models::Device;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/devices/knowndevice", get(known_device))
        .route(
            "/api/devices/identifier/{device_id}",
            get(get_device_by_id),
        )
        .route(
            "/api/devices/{device_id}",
            axum::routing::delete(delete_device),
        )
        .route(
            "/api/devices/identifier/{device_id}/token",
            post(set_push_token).put(set_push_token),
        )
        .route(
            "/api/devices/identifier/{device_id}/clear-token",
            post(clear_push_token).put(clear_push_token),
        )
}

fn err_json(code: StatusCode, msg: &str) -> (StatusCode, Json<Value>) {
    (code, Json(json!({ "ErrorModel": { "Message": msg }, "Object": "error", "Message": msg })))
}

fn device_json(d: &Device) -> Value {
    json!({
        "Object": "device",
        "Id": d.uuid,
        "Name": d.name,
        "Type": d.atype,
        "CreationDate": d.created_at,
        "RevisionDate": d.updated_at,
    })
}

#[worker::send]
async fn get_device_by_id(
    AxumState(state): AxumState<AppState>,
    headers: Headers,
    Path(device_id): Path<String>,
) -> impl IntoResponse {
    match Device::find(&state.db, &device_id, &headers.user.uuid).await {
        Ok(Some(d)) => (StatusCode::OK, Json(device_json(&d))),
        Ok(None) => err_json(StatusCode::NOT_FOUND, "Device not found"),
        Err(_) => err_json(StatusCode::INTERNAL_SERVER_ERROR, "database error"),
    }
}

/// `GET /api/devices/knowndevice` — Bitwarden web/mobile probe to ask "have I
/// seen this email+device combo before?". Returns a boolean as a bare JSON
/// value. Used so first-time logins from a new device can prompt the user.
#[worker::send]
async fn known_device(
    AxumState(state): AxumState<AppState>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    let email = headers
        .get("x-request-email")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let device_id = headers
        .get("x-device-identifier")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);

    let (Some(email), Some(device_id)) = (email, device_id) else {
        // Bitwarden's client also accepts query/path style; absent → false.
        return (StatusCode::OK, Json(Value::Bool(false)));
    };
    let user = match crate::db::models::User::find_by_email(&state.db, &email.to_lowercase()).await {
        Ok(Some(u)) => u,
        _ => return (StatusCode::OK, Json(Value::Bool(false))),
    };
    let known = matches!(Device::find(&state.db, &device_id, &user.uuid).await, Ok(Some(_)));
    (StatusCode::OK, Json(Value::Bool(known)))
}

#[derive(Deserialize)]
struct PushTokenBody {
    #[serde(rename = "pushToken", alias = "PushToken")]
    push_token: String,
}

#[worker::send]
async fn set_push_token(
    AxumState(state): AxumState<AppState>,
    headers: Headers,
    Path(device_id): Path<String>,
    Json(body): Json<PushTokenBody>,
) -> impl IntoResponse {
    let mut device = match Device::find(&state.db, &device_id, &headers.user.uuid).await {
        Ok(Some(d)) => d,
        Ok(None) => return err_json(StatusCode::NOT_FOUND, "Device not found"),
        Err(_) => return err_json(StatusCode::INTERNAL_SERVER_ERROR, "database error"),
    };
    device.push_token = Some(body.push_token);
    device.push_uuid = Some(uuid::Uuid::new_v4().to_string());
    if device.save(&state.db).await.is_err() {
        return err_json(StatusCode::INTERNAL_SERVER_ERROR, "save failed");
    }
    (StatusCode::OK, Json(device_json(&device)))
}

#[worker::send]
async fn clear_push_token(
    AxumState(state): AxumState<AppState>,
    headers: Headers,
    Path(device_id): Path<String>,
) -> impl IntoResponse {
    let mut device = match Device::find(&state.db, &device_id, &headers.user.uuid).await {
        Ok(Some(d)) => d,
        Ok(None) => return err_json(StatusCode::NOT_FOUND, "Device not found"),
        Err(_) => return err_json(StatusCode::INTERNAL_SERVER_ERROR, "database error"),
    };
    device.push_token = None;
    device.push_uuid = None;
    if device.save(&state.db).await.is_err() {
        return err_json(StatusCode::INTERNAL_SERVER_ERROR, "save failed");
    }
    (StatusCode::OK, Json(device_json(&device)))
}

/// Delete a device by uuid. The user must own the device. Used by
/// "Sign out of all devices" and per-device sign-out from the web vault.
#[worker::send]
async fn delete_device(
    AxumState(state): AxumState<AppState>,
    headers: Headers,
    Path(device_id): Path<String>,
) -> impl IntoResponse {
    let device = match Device::find(&state.db, &device_id, &headers.user.uuid).await {
        Ok(Some(d)) => d,
        Ok(None) => return err_json(StatusCode::NOT_FOUND, "Device not found"),
        Err(_) => return err_json(StatusCode::INTERNAL_SERVER_ERROR, "database error"),
    };
    if device.delete(&state.db).await.is_err() {
        return err_json(StatusCode::INTERNAL_SERVER_ERROR, "delete failed");
    }
    crate::api::notify::notify_user(
        &state,
        &headers.user.uuid,
        crate::api::notify::kind::LOG_OUT,
        &headers.user.uuid,
    )
    .await;
    (StatusCode::OK, Json(json!({})))
}
