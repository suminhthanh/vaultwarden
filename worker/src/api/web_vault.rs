//! Serve the prebuilt Bitwarden web client SPA from the `WEB_VAULT` R2 bucket.
//!
//! Upstream Vaultwarden bundles `dani-garcia/bw_web_builds` releases as a
//! `web-vault/` directory served from the filesystem. We don't have a
//! filesystem; we upload the same tarball into R2 and stream files from there.
//! The router is intentionally a single fallback layer: any GET that didn't
//! match an API route falls through here, gets resolved against R2, and
//! returns the file (or index.html for SPA paths).

use axum::{
    Router,
    body::Body,
    extract::{Request, State as AxumState},
    http::{StatusCode, header},
    response::Response,
    routing::get,
};

use crate::AppState;

pub fn routes() -> Router<AppState> {
    Router::new().fallback(get(serve))
}

#[worker::send]
async fn serve(AxumState(state): AxumState<AppState>, req: Request) -> Response {
    let path = req.uri().path().trim_start_matches('/');
    // Bare root → index.html. Avoids leaking the bucket listing.
    let lookup_key = if path.is_empty() { "index.html" } else { path };

    if let Some(resp) = fetch_object(&state, lookup_key).await {
        return resp;
    }

    // SPA fallback — every unknown path that doesn't have a file extension
    // (so Bitwarden's client-side router can resolve it).
    if !lookup_key.contains('.')
        && let Some(resp) = fetch_object(&state, "index.html").await
    {
        return resp;
    }

    not_found()
}

async fn fetch_object(state: &AppState, key: &str) -> Option<Response> {
    let obj = state.web_vault.get(key).execute().await.ok()??;
    let body = obj.body()?;
    let bytes = body.bytes().await.ok()?;
    let mime = guess_mime(key);
    Some(
        Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, mime)
            .header(header::CONTENT_LENGTH, bytes.len().to_string())
            .header(header::CACHE_CONTROL, cache_control_for(key))
            .body(Body::from(bytes))
            .unwrap_or_else(|_| not_found()),
    )
}

fn not_found() -> Response {
    Response::builder()
        .status(StatusCode::NOT_FOUND)
        .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(Body::from(
            "Web vault not uploaded. See DEPLOY.md → 'Upload the web vault'.",
        ))
        .unwrap()
}

fn guess_mime(key: &str) -> &'static str {
    let ext = key.rsplit('.').next().unwrap_or("");
    match ext {
        "html" | "htm" => "text/html; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "js" | "mjs" => "application/javascript; charset=utf-8",
        "json" => "application/json; charset=utf-8",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "webp" => "image/webp",
        "gif" => "image/gif",
        "ico" => "image/x-icon",
        "woff" => "font/woff",
        "woff2" => "font/woff2",
        "ttf" => "font/ttf",
        "wasm" => "application/wasm",
        "txt" => "text/plain; charset=utf-8",
        "map" => "application/json; charset=utf-8",
        _ => "application/octet-stream",
    }
}

fn cache_control_for(key: &str) -> &'static str {
    // Bitwarden's web client ships hashed asset filenames (e.g. main.abc123.js)
    // — those can be cached aggressively. index.html and untagged HTML must
    // revalidate so users pick up new releases without a hard refresh.
    if key.ends_with(".html") || key == "index.html" {
        "no-cache, must-revalidate"
    } else {
        "public, max-age=31536000, immutable"
    }
}
