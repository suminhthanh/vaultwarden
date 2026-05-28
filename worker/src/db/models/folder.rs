use chrono::{NaiveDateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use worker::{D1Database, wasm_bindgen::JsValue};

use crate::db::DbResult;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Folder {
    pub uuid: String,
    pub created_at: String,
    pub updated_at: String,
    pub user_uuid: String,
    pub name: String,
}

impl Folder {
    pub fn new(user_uuid: String, name: String) -> Self {
        let now = format_date(&Utc::now().naive_utc());
        Self {
            uuid: Uuid::new_v4().to_string(),
            created_at: now.clone(),
            updated_at: now,
            user_uuid,
            name,
        }
    }

    pub async fn find_by_uuid(db: &D1Database, uuid: &str) -> DbResult<Option<Self>> {
        let stmt = db.prepare("SELECT * FROM folders WHERE uuid = ?1").bind(&[JsValue::from_str(uuid)])?;
        Ok(stmt.first::<Self>(None).await?)
    }

    pub async fn find_by_user(db: &D1Database, user_uuid: &str) -> DbResult<Vec<Self>> {
        let stmt =
            db.prepare("SELECT * FROM folders WHERE user_uuid = ?1").bind(&[JsValue::from_str(user_uuid)])?;
        Ok(stmt.all().await?.results::<Self>()?)
    }

    pub async fn save(&mut self, db: &D1Database) -> DbResult<()> {
        self.updated_at = format_date(&Utc::now().naive_utc());
        let stmt = db
            .prepare(
                "INSERT INTO folders (uuid, created_at, updated_at, user_uuid, name) \
                 VALUES (?1, ?2, ?3, ?4, ?5) \
                 ON CONFLICT(uuid) DO UPDATE SET updated_at = excluded.updated_at, \
                 user_uuid = excluded.user_uuid, name = excluded.name",
            )
            .bind(&[
                JsValue::from_str(&self.uuid),
                JsValue::from_str(&self.created_at),
                JsValue::from_str(&self.updated_at),
                JsValue::from_str(&self.user_uuid),
                JsValue::from_str(&self.name),
            ])?;
        let _result = stmt.run().await?;
        Ok(())
    }

    pub async fn delete(self, db: &D1Database) -> DbResult<()> {
        let stmt = db.prepare("DELETE FROM folders WHERE uuid = ?1").bind(&[JsValue::from_str(&self.uuid)])?;
        let _result = stmt.run().await?;
        Ok(())
    }
}

fn format_date(dt: &NaiveDateTime) -> String {
    dt.and_utc().to_rfc3339_opts(chrono::SecondsFormat::Micros, true)
}
