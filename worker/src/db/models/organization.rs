use serde::{Deserialize, Serialize};
use uuid::Uuid;
use worker::{D1Database, wasm_bindgen::JsValue};

use crate::db::DbResult;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Organization {
    pub uuid: String,
    pub name: String,
    pub billing_email: String,
    pub private_key: Option<String>,
    pub public_key: Option<String>,
}

impl Organization {
    pub fn new(name: String, billing_email: String) -> Self {
        Self {
            uuid: Uuid::new_v4().to_string(),
            name,
            billing_email: billing_email.to_lowercase(),
            private_key: None,
            public_key: None,
        }
    }

    pub async fn find_by_uuid(db: &D1Database, uuid: &str) -> DbResult<Option<Self>> {
        let stmt = db.prepare("SELECT * FROM organizations WHERE uuid = ?1").bind(&[JsValue::from_str(uuid)])?;
        Ok(stmt.first::<Self>(None).await?)
    }

    pub async fn save(&self, db: &D1Database) -> DbResult<()> {
        let stmt = db
            .prepare(
                "INSERT INTO organizations (uuid, name, billing_email, private_key, public_key) \
                 VALUES (?1, ?2, ?3, ?4, ?5) \
                 ON CONFLICT(uuid) DO UPDATE SET name = excluded.name, billing_email = excluded.billing_email, \
                 private_key = excluded.private_key, public_key = excluded.public_key",
            )
            .bind(&[
                JsValue::from_str(&self.uuid),
                JsValue::from_str(&self.name),
                JsValue::from_str(&self.billing_email),
                opt_str(&self.private_key),
                opt_str(&self.public_key),
            ])?;
        let _result = stmt.run().await?;
        Ok(())
    }

    pub async fn delete(self, db: &D1Database) -> DbResult<()> {
        let stmt =
            db.prepare("DELETE FROM organizations WHERE uuid = ?1").bind(&[JsValue::from_str(&self.uuid)])?;
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
