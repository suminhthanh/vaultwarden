//! Lightweight observability: structured JSON log lines + optional Cloudflare
//! Analytics Engine. Logpush picks up everything `console.log`d.
//!
//! Analytics Engine is opt-in via the `ANALYTICS` binding in `wrangler.jsonc`.
//! When the binding isn't configured, the helper silently no-ops so dev runs
//! don't need to provision a dataset.
#![allow(dead_code)]

use serde_json::json;

#[derive(Clone)]
pub struct Telemetry {
    dataset: Option<std::sync::Arc<worker::AnalyticsEngineDataset>>,
}

impl Telemetry {
    pub fn from_env(env: &worker::Env) -> Self {
        let dataset = env.analytics_engine("ANALYTICS").ok().map(std::sync::Arc::new);
        Self { dataset }
    }

    /// Record one event. We log a one-line JSON object for Logpush regardless,
    /// then write_data_point to AE if configured.
    pub fn record(&self, event: &str, fields: &[(&str, &str)]) {
        let mut obj = serde_json::Map::new();
        obj.insert("event".into(), json!(event));
        for (k, v) in fields {
            obj.insert((*k).into(), json!(v));
        }
        worker::console_log!("{}", serde_json::Value::Object(obj));

        if let Some(ds) = &self.dataset {
            let blobs: Vec<worker::BlobType> = std::iter::once(event.to_owned().into())
                .chain(fields.iter().map(|(_, v)| (*v).to_owned().into()))
                .collect();
            let dp = worker::AnalyticsEngineDataPointBuilder::new().indexes([event]).blobs(blobs).build();
            let _result = ds.write_data_point(&dp);
        }
    }
}
