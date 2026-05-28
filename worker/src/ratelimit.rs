//! Sliding-window rate limiter backed by Workers KV.
//!
//! Each call increments a per-bucket counter under a key like `rl:login:1.2.3.4:1700000`
//! (suffix = window start in seconds), then sums the current and previous bucket
//! values to estimate the rate. The window suffix changes naturally over time so
//! KV's eventual consistency is fine — keys auto-expire via TTL.

use worker::kv::KvStore;

pub struct RateLimit {
    pub kind: &'static str,
    pub window_secs: u64,
    pub limit: u32,
}

pub const LOGIN_LIMIT: RateLimit = RateLimit { kind: "login", window_secs: 60, limit: 200 };
pub const REGISTER_LIMIT: RateLimit = RateLimit { kind: "register", window_secs: 3600, limit: 500 };
/// Caps email-2FA send + protected-action OTP + password-hint emails.
/// Keyed by user UUID (or email) so a single attacker can't spam someone
/// else's inbox even from many IPs.
pub const EMAIL_SEND_LIMIT: RateLimit = RateLimit { kind: "mail", window_secs: 3600, limit: 30 };

pub async fn check(kv: &KvStore, limit: &RateLimit, identifier: &str) -> bool {
    let now: u64 = worker::Date::now().as_millis() / 1000;
    let current_window = now / limit.window_secs;
    let prev_window = current_window.saturating_sub(1);

    let current_key = format!("rl:{}:{identifier}:{current_window}", limit.kind);
    let prev_key = format!("rl:{}:{identifier}:{prev_window}", limit.kind);

    let current = read_count(kv, &current_key).await;
    let prev = read_count(kv, &prev_key).await;

    // Weight the previous window by what fraction of the current window has elapsed.
    let elapsed = (now % limit.window_secs) as f64 / limit.window_secs as f64;
    let estimated = (current as f64) + (prev as f64) * (1.0 - elapsed);
    if estimated >= limit.limit as f64 {
        return false;
    }

    let new_count = current + 1;
    if let Ok(builder) = kv.put(&current_key, new_count.to_string()) {
        let _result = builder.expiration_ttl(limit.window_secs * 2 + 5).execute().await;
    }
    true
}

async fn read_count(kv: &KvStore, key: &str) -> u64 {
    match kv.get(key).text().await {
        Ok(Some(s)) => s.parse().unwrap_or(0),
        _ => 0,
    }
}
