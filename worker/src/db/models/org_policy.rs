use serde::{Deserialize, Serialize};
use uuid::Uuid;
use worker::{D1Database, wasm_bindgen::JsValue};

use crate::db::DbResult;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrgPolicy {
    pub uuid: String,
    pub org_uuid: String,
    pub atype: i32,
    pub enabled: i32,
    pub data: String,
}

impl OrgPolicy {
    pub fn new(org_uuid: String, atype: i32, data: String) -> Self {
        Self {
            uuid: Uuid::new_v4().to_string(),
            org_uuid,
            atype,
            enabled: 0,
            data,
        }
    }

    pub async fn find_by_uuid(db: &D1Database, uuid: &str) -> DbResult<Option<Self>> {
        let stmt = db
            .prepare("SELECT * FROM org_policies WHERE uuid = ?1")
            .bind(&[JsValue::from_str(uuid)])?;
        Ok(stmt.first::<Self>(None).await?)
    }

    pub async fn find_by_org(db: &D1Database, org_uuid: &str) -> DbResult<Vec<Self>> {
        let stmt = db
            .prepare("SELECT * FROM org_policies WHERE org_uuid = ?1")
            .bind(&[JsValue::from_str(org_uuid)])?;
        Ok(stmt.all().await?.results::<Self>()?)
    }

    pub async fn find_by_org_and_type(
        db: &D1Database,
        org_uuid: &str,
        atype: i32,
    ) -> DbResult<Option<Self>> {
        let stmt = db
            .prepare("SELECT * FROM org_policies WHERE org_uuid = ?1 AND atype = ?2")
            .bind(&[JsValue::from_str(org_uuid), JsValue::from_f64(atype as f64)])?;
        Ok(stmt.first::<Self>(None).await?)
    }

    pub async fn save(&self, db: &D1Database) -> DbResult<()> {
        let stmt = db
            .prepare(
                "INSERT INTO org_policies (uuid, org_uuid, atype, enabled, data) \
                 VALUES (?1, ?2, ?3, ?4, ?5) \
                 ON CONFLICT(uuid) DO UPDATE SET \
                 org_uuid = excluded.org_uuid, atype = excluded.atype, \
                 enabled = excluded.enabled, data = excluded.data",
            )
            .bind(&[
                JsValue::from_str(&self.uuid),
                JsValue::from_str(&self.org_uuid),
                JsValue::from_f64(self.atype as f64),
                JsValue::from_f64(self.enabled as f64),
                JsValue::from_str(&self.data),
            ])?;
        let _result = stmt.run().await?;
        Ok(())
    }

    pub async fn delete(self, db: &D1Database) -> DbResult<()> {
        let stmt = db
            .prepare("DELETE FROM org_policies WHERE uuid = ?1")
            .bind(&[JsValue::from_str(&self.uuid)])?;
        let _result = stmt.run().await?;
        Ok(())
    }
}
