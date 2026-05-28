use axum::{
    Router,
    extract::{Query, State as AxumState},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
};
use serde::Deserialize;

use crate::AppState;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/notifications/hub", get(hub))
        .route("/notifications/hub/negotiate", axum::routing::post(negotiate))
        .route("/notifications/anonymous-hub", get(anon_hub))
        .route("/notifications/anonymous-hub/negotiate", axum::routing::post(negotiate))
}

async fn negotiate() -> impl IntoResponse {
    // Bitwarden web client first POSTs here to learn the SignalR transport URL.
    // We only support raw WebSockets; report that with a fixed connection token.
    axum::Json(serde_json::json!({
        "connectionId": "vaultwarden-worker",
        "negotiateVersion": 0,
        "availableTransports": [
            { "transport": "WebSockets", "transferFormats": ["Text", "Binary"] }
        ],
    }))
}

#[derive(Deserialize)]
struct HubQuery {
    #[serde(default)]
    access_token: Option<String>,
    #[serde(default)]
    token: Option<String>,
}

#[worker::send]
async fn hub(
    AxumState(state): AxumState<AppState>,
    headers: HeaderMap,
    Query(q): Query<HubQuery>,
) -> Response {
    // Bitwarden's SignalR client passes the JWT via `?access_token=...` on the
    // WebSocket upgrade — Authorization header isn't available cross-browser.
    let token = q
        .access_token
        .or(q.token)
        .or_else(|| extract_token(&headers))
        .unwrap_or_default();
    if token.is_empty() {
        return error("missing access_token");
    }
    let claims: crate::auth::LoginJwtClaims = match state.keys.decode(&token, &state.keys.login_issuer) {
        Ok(c) => c,
        Err(e) => return error(&format!("invalid token: {e}")),
    };

    let ns = state.user_notifications.as_ref();
    let id = match ns.id_from_name(&claims.sub) {
        Ok(id) => id,
        Err(_) => return error("DO id_from_name failed"),
    };
    let stub = match id.get_stub() {
        Ok(s) => s,
        Err(_) => return error("DO stub failed"),
    };

    let req = match build_upgrade_request() {
        Ok(r) => r,
        Err(_) => return error("DO request build failed"),
    };
    let result = stub.fetch_with_request(req).await;
    drop(stub);
    match result {
        Ok(resp) => {
            let http: axum::http::Response<axum::body::Body> = match resp.try_into() {
                Ok(r) => r,
                Err(_) => return error("DO response convert failed"),
            };
            http
        }
        Err(_) => error("DO fetch failed"),
    }
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct AnonHubQuery {
    #[serde(default, alias = "Token", alias = "token")]
    token: Option<String>,
}

/// Anonymous notifications hub — used by clients that have requested
/// passwordless login and are waiting for an approval push. The "auth" here
/// is the auth-request UUID itself, which we route into a per-request
/// Durable Object so the caller can be poked when the response lands.
#[worker::send]
async fn anon_hub(
    AxumState(state): AxumState<AppState>,
    Query(q): Query<AnonHubQuery>,
) -> Response {
    let key = match q.token.as_deref() {
        Some(t) if !t.is_empty() => t,
        _ => return error("missing token"),
    };
    let ns = state.anon_notifications.as_ref();
    let id = match ns.id_from_name(key) {
        Ok(id) => id,
        Err(_) => return error("DO id_from_name failed"),
    };
    let stub = match id.get_stub() {
        Ok(s) => s,
        Err(_) => return error("DO stub failed"),
    };
    let req = match build_upgrade_request() {
        Ok(r) => r,
        Err(_) => return error("DO request build failed"),
    };
    let result = stub.fetch_with_request(req).await;
    drop(stub);
    match result {
        Ok(resp) => match resp.try_into() {
            Ok(r) => r,
            Err(_) => error("DO response convert failed"),
        },
        Err(_) => error("DO fetch failed"),
    }
}

fn extract_token(headers: &HeaderMap) -> Option<String> {
    if let Some(auth) = headers.get(axum::http::header::AUTHORIZATION).and_then(|v| v.to_str().ok())
        && let Some(rest) = auth.strip_prefix("Bearer ").or_else(|| auth.strip_prefix("bearer "))
    {
        return Some(rest.to_owned());
    }
    None
}

fn build_upgrade_request() -> worker::Result<worker::Request> {
    let hdrs = worker::Headers::new();
    hdrs.set("upgrade", "websocket")?;
    let mut init = worker::RequestInit::new();
    init.with_method(worker::Method::Get);
    init.with_headers(hdrs);
    worker::Request::new_with_init("https://do/connect", &init)
}

fn error(msg: &str) -> Response {
    (StatusCode::BAD_REQUEST, msg.to_owned()).into_response()
}
