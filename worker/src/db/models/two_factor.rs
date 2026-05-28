use serde::{Deserialize, Serialize};
use uuid::Uuid;
use worker::{D1Database, wasm_bindgen::JsValue};

use crate::db::DbResult;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TwoFactor {
    pub uuid: String,
    pub user_uuid: String,
    pub atype: i32,
    pub enabled: i32,
    pub data: String,
    pub last_used: i32,
}

impl TwoFactor {
    pub fn new(user_uuid: String, atype: i32, data: String) -> Self {
        Self {
            uuid: Uuid::new_v4().to_string(),
            user_uuid,
            atype,
            enabled: 1,
            data,
            last_used: 0,
        }
    }

    pub async fn find_by_uuid(db: &D1Database, uuid: &str) -> DbResult<Option<Self>> {
        let stmt = db
            .prepare("SELECT * FROM twofactor WHERE uuid = ?1")
            .bind(&[JsValue::from_str(uuid)])?;
        Ok(stmt.first::<Self>(None).await?)
    }

    pub async fn find_by_user(db: &D1Database, user_uuid: &str) -> DbResult<Vec<Self>> {
        let stmt = db
            .prepare("SELECT * FROM twofactor WHERE user_uuid = ?1")
            .bind(&[JsValue::from_str(user_uuid)])?;
        Ok(stmt.all().await?.results::<Self>()?)
    }

    pub async fn find_by_user_and_type(
        db: &D1Database,
        user_uuid: &str,
        atype: i32,
    ) -> DbResult<Option<Self>> {
        let stmt = db
            .prepare("SELECT * FROM twofactor WHERE user_uuid = ?1 AND atype = ?2")
            .bind(&[JsValue::from_str(user_uuid), JsValue::from_f64(atype as f64)])?;
        Ok(stmt.first::<Self>(None).await?)
    }

    pub async fn save(&self, db: &D1Database) -> DbResult<()> {
        let stmt = db
            .prepare(
                "INSERT INTO twofactor (uuid, user_uuid, atype, enabled, data, last_used) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6) \
                 ON CONFLICT(uuid) DO UPDATE SET \
                 user_uuid = excluded.user_uuid, atype = excluded.atype, \
                 enabled = excluded.enabled, data = excluded.data, \
                 last_used = excluded.last_used",
            )
            .bind(&[
                JsValue::from_str(&self.uuid),
                JsValue::from_str(&self.user_uuid),
                JsValue::from_f64(self.atype as f64),
                JsValue::from_f64(self.enabled as f64),
                JsValue::from_str(&self.data),
                JsValue::from_f64(self.last_used as f64),
            ])?;
        let _result = stmt.run().await?;
        Ok(())
    }

    pub async fn delete(self, db: &D1Database) -> DbResult<()> {
        let stmt = db
            .prepare("DELETE FROM twofactor WHERE uuid = ?1")
            .bind(&[JsValue::from_str(&self.uuid)])?;
        let _result = stmt.run().await?;
        Ok(())
    }
}
