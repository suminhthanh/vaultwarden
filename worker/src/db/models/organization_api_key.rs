use chrono::{NaiveDateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use worker::{D1Database, wasm_bindgen::JsValue};

use crate::db::DbResult;

/// `organization_api_key` has a composite primary key `(uuid, org_uuid)`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrganizationApiKey {
    pub uuid: String,
    pub org_uuid: String,
    pub atype: i32,
    pub api_key: String,
    pub revision_date: String,
}

impl OrganizationApiKey {
    pub fn new(org_uuid: String, atype: i32, api_key: String) -> Self {
        Self {
            uuid: Uuid::new_v4().to_string(),
            org_uuid,
            atype,
            api_key,
            revision_date: format_date(&Utc::now().naive_utc()),
        }
    }

    pub async fn find_by_org(db: &D1Database, org_uuid: &str) -> DbResult<Vec<Self>> {
        let stmt = db
            .prepare("SELECT * FROM organization_api_key WHERE org_uuid = ?1")
            .bind(&[JsValue::from_str(org_uuid)])?;
        Ok(stmt.all().await?.results::<Self>()?)
    }

    pub async fn save(&mut self, db: &D1Database) -> DbResult<()> {
        self.revision_date = format_date(&Utc::now().naive_utc());
        let stmt = db
            .prepare(
                "INSERT INTO organization_api_key (uuid, org_uuid, atype, api_key, revision_date) \
                 VALUES (?1, ?2, ?3, ?4, ?5) \
                 ON CONFLICT(uuid, org_uuid) DO UPDATE SET \
                 atype = excluded.atype, api_key = excluded.api_key, \
                 revision_date = excluded.revision_date",
            )
            .bind(&[
                JsValue::from_str(&self.uuid),
                JsValue::from_str(&self.org_uuid),
                JsValue::from_f64(self.atype as f64),
                JsValue::from_str(&self.api_key),
                JsValue::from_str(&self.revision_date),
            ])?;
        let _result = stmt.run().await?;
        Ok(())
    }

    pub async fn delete(self, db: &D1Database) -> DbResult<()> {
        let stmt = db
            .prepare("DELETE FROM organization_api_key WHERE uuid = ?1 AND org_uuid = ?2")
            .bind(&[JsValue::from_str(&self.uuid), JsValue::from_str(&self.org_uuid)])?;
        let _result = stmt.run().await?;
        Ok(())
    }
}

fn format_date(dt: &NaiveDateTime) -> String {
    dt.and_utc().to_rfc3339_opts(chrono::SecondsFormat::Micros, true)
}
