//! Admin-tunable runtime configuration backed by Workers KV.
//!
//! Most config comes from env vars (immutable across the request lifetime).
//! A small subset is admin-tunable from the panel — that subset lives in KV
//! under the key `config:overrides` as a JSON object, and is read once per
//! cold start into a `OnceCell`. Writes from the admin panel update both KV
//! and the in-memory copy.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct ConfigOverrides {
    pub signups_allowed: Option<bool>,
    pub signups_verify: Option<bool>,
    pub invitations_allowed: Option<bool>,
    pub disable_invitations: Option<bool>,
    pub email_2fa_enabled: Option<bool>,
    pub require_device_email: Option<bool>,
    pub max_login_attempts: Option<u32>,
}

const KEY: &str = "config:overrides";

pub async fn load(kv: &worker::kv::KvStore) -> ConfigOverrides {
    match kv.get(KEY).text().await {
        Ok(Some(s)) => serde_json::from_str(&s).unwrap_or_default(),
        _ => ConfigOverrides::default(),
    }
}

pub async fn save(kv: &worker::kv::KvStore, overrides: &ConfigOverrides) -> Result<(), worker::Error> {
    let body = serde_json::to_string(overrides).map_err(|e| worker::Error::RustError(e.to_string()))?;
    kv.put(KEY, body)
        .map_err(|e| worker::Error::RustError(e.to_string()))?
        .execute()
        .await
        .map_err(|e| worker::Error::RustError(e.to_string()))
}
