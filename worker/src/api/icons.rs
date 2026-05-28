//! Favicon proxy backed by R2.
//!
//! Path: `GET /icons/{host}/icon.png`. We treat the host as the cache key.
//! On a miss we fetch `https://{host}/favicon.ico` (and a couple of common
//! fallbacks), stash the bytes in R2, and return them. On a hit we serve
//! straight from R2. Bitwarden clients hammer this for every login row,
//! which is why upstream caches it on disk; we use R2 instead.

use axum::{
    Router,
    body::Body,
    extract::{Path, State as AxumState},
    http::{StatusCode, header},
    response::Response,
    routing::get,
};

use crate::AppState;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/icons/{host}/icon.png", get(icon))
        .route("/{host}/icon.png", get(icon))
}

const CACHE_TTL_SECS: u64 = 60 * 60 * 24 * 30; // 30 days
const MAX_BYTES: usize = 5 * 1024 * 1024; // 5 MiB cap, matches upstream

#[worker::send]
async fn icon(
    AxumState(state): AxumState<AppState>,
    Path(host): Path<String>,
) -> Response {
    let host = host.trim().to_ascii_lowercase();
    if !is_valid_host(&host) {
        return fallback_response();
    }

    let key = format!("{host}.png");
    if let Ok(Some(obj)) = state.icons.get(&key).execute().await
        && let Some(body) = obj.body()
        && let Ok(bytes) = body.bytes().await
    {
        return ok_png(bytes);
    }

    match fetch_remote(&host).await {
        Some(bytes) => {
            let _put = state.icons.put(&key, bytes.clone()).execute().await;
            ok_png(bytes)
        }
        None => fallback_response(),
    }
}

fn is_valid_host(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 255
        && host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == ':')
}

async fn fetch_remote(host: &str) -> Option<Vec<u8>> {
    // Try a small set of well-known favicon URLs in order. The first one
    // returning a 200 with an image-shaped Content-Type wins.
    for url in [
        format!("https://{host}/apple-touch-icon.png"),
        format!("https://{host}/favicon.ico"),
        format!("https://icons.duckduckgo.com/ip3/{host}.ico"),
    ] {
        if let Some(bytes) = try_one(&url).await {
            return Some(bytes);
        }
    }
    None
}

async fn try_one(url: &str) -> Option<Vec<u8>> {
    let req = worker::Request::new(url, worker::Method::Get).ok()?;
    let mut resp = worker::Fetch::Request(req).send().await.ok()?;
    if resp.status_code() != 200 {
        return None;
    }
    let bytes = resp.bytes().await.ok()?;
    if bytes.is_empty() || bytes.len() > MAX_BYTES {
        return None;
    }
    // Crude image sniff: PNG / ICO / SVG / JPEG / WEBP / GIF.
    let head = &bytes[..bytes.len().min(8)];
    let looks_image = head.starts_with(b"\x89PNG")
        || head.starts_with(b"\x00\x00\x01\x00")
        || head.starts_with(b"\xff\xd8\xff")
        || head.starts_with(b"GIF8")
        || head.starts_with(b"RIFF")
        || head.starts_with(b"<?xml")
        || head.starts_with(b"<svg")
        || head.starts_with(b"<!DOC");
    if !looks_image {
        return None;
    }
    Some(bytes)
}

fn ok_png(bytes: Vec<u8>) -> Response {
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "image/png")
        .header(header::CONTENT_LENGTH, bytes.len().to_string())
        .header(header::CACHE_CONTROL, format!("public, max-age={CACHE_TTL_SECS}, immutable"))
        .body(Body::from(bytes))
        .unwrap_or_else(|_| fallback_response())
}

/// 1x1 transparent PNG — what Bitwarden falls back to when the upstream
/// favicon proxy can't fetch one. Pre-encoded literal so it's free.
const TRANSPARENT_PNG: &[u8] = &[
    0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52,
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x06, 0x00, 0x00, 0x00, 0x1F, 0x15, 0xC4,
    0x89, 0x00, 0x00, 0x00, 0x0D, 0x49, 0x44, 0x41, 0x54, 0x78, 0x9C, 0x63, 0x00, 0x01, 0x00, 0x00,
    0x05, 0x00, 0x01, 0x0D, 0x0A, 0x2D, 0xB4, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4E, 0x44, 0xAE,
    0x42, 0x60, 0x82,
];

fn fallback_response() -> Response {
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "image/png")
        .header(header::CONTENT_LENGTH, TRANSPARENT_PNG.len().to_string())
        .header(header::CACHE_CONTROL, "public, max-age=600")
        .body(Body::from(TRANSPARENT_PNG))
        .unwrap()
}
