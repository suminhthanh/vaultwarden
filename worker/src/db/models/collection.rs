use serde::{Deserialize, Serialize};
use uuid::Uuid;
use worker::{D1Database, wasm_bindgen::JsValue};

use crate::db::DbResult;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Collection {
    pub uuid: String,
    pub org_uuid: String,
    pub name: String,
    pub external_id: Option<String>,
}

impl Collection {
    pub fn new(org_uuid: String, name: String) -> Self {
        Self {
            uuid: Uuid::new_v4().to_string(),
            org_uuid,
            name,
            external_id: None,
        }
    }

    pub async fn find_by_uuid(db: &D1Database, uuid: &str) -> DbResult<Option<Self>> {
        let stmt = db.prepare("SELECT * FROM collections WHERE uuid = ?1").bind(&[JsValue::from_str(uuid)])?;
        Ok(stmt.first::<Self>(None).await?)
    }

    pub async fn find_by_org(db: &D1Database, org_uuid: &str) -> DbResult<Vec<Self>> {
        let stmt =
            db.prepare("SELECT * FROM collections WHERE org_uuid = ?1").bind(&[JsValue::from_str(org_uuid)])?;
        Ok(stmt.all().await?.results::<Self>()?)
    }

    pub async fn save(&self, db: &D1Database) -> DbResult<()> {
        let stmt = db
            .prepare(
                "INSERT INTO collections (uuid, org_uuid, name, external_id) VALUES (?1, ?2, ?3, ?4) \
                 ON CONFLICT(uuid) DO UPDATE SET org_uuid = excluded.org_uuid, name = excluded.name, \
                 external_id = excluded.external_id",
            )
            .bind(&[
                JsValue::from_str(&self.uuid),
                JsValue::from_str(&self.org_uuid),
                JsValue::from_str(&self.name),
                opt_str(&self.external_id),
            ])?;
        let _result = stmt.run().await?;
        Ok(())
    }

    pub async fn delete(self, db: &D1Database) -> DbResult<()> {
        let stmt = db.prepare("DELETE FROM collections WHERE uuid = ?1").bind(&[JsValue::from_str(&self.uuid)])?;
        let _result = stmt.run().await?;
        Ok(())
    }
}

fn opt_str(value: &Option<String>) -> JsValue {
    match value {
        Some(s) => JsValue::from_str(s),
        None => JsValue::NULL,
    }
}
