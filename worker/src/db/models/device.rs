use chrono::{NaiveDateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use worker::{D1Database, wasm_bindgen::JsValue};

use crate::db::DbResult;

/// `devices` has a composite primary key `(uuid, user_uuid)`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Device {
    pub uuid: String,
    pub created_at: String,
    pub updated_at: String,
    pub user_uuid: String,
    pub name: String,
    pub atype: i32,
    pub push_token: Option<String>,
    pub refresh_token: String,
    pub twofactor_remember: Option<String>,
    pub push_uuid: Option<String>,
}

impl Device {
    pub fn new(user_uuid: String, name: String, atype: i32) -> Self {
        let now = format_date(&Utc::now().naive_utc());
        Self {
            uuid: Uuid::new_v4().to_string(),
            created_at: now.clone(),
            updated_at: now,
            user_uuid,
            name,
            atype,
            push_token: None,
            refresh_token: String::new(),
            twofactor_remember: None,
            push_uuid: None,
        }
    }

    pub async fn find(db: &D1Database, uuid: &str, user_uuid: &str) -> DbResult<Option<Self>> {
        let stmt = db
            .prepare("SELECT * FROM devices WHERE uuid = ?1 AND user_uuid = ?2")
            .bind(&[JsValue::from_str(uuid), JsValue::from_str(user_uuid)])?;
        Ok(stmt.first::<Self>(None).await?)
    }

    pub async fn find_by_user(db: &D1Database, user_uuid: &str) -> DbResult<Vec<Self>> {
        let stmt = db.prepare("SELECT * FROM devices WHERE user_uuid = ?1").bind(&[JsValue::from_str(user_uuid)])?;
        Ok(stmt.all().await?.results::<Self>()?)
    }

    pub async fn find_by_refresh_token(db: &D1Database, refresh_token: &str) -> DbResult<Option<Self>> {
        let stmt = db
            .prepare("SELECT * FROM devices WHERE refresh_token = ?1 LIMIT 1")
            .bind(&[JsValue::from_str(refresh_token)])?;
        Ok(stmt.first::<Self>(None).await?)
    }

    pub async fn save(&mut self, db: &D1Database) -> DbResult<()> {
        self.updated_at = format_date(&Utc::now().naive_utc());
        let stmt = db
            .prepare(
                "INSERT INTO devices (uuid, created_at, updated_at, user_uuid, name, atype, push_token, \
                 refresh_token, twofactor_remember, push_uuid) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10) \
                 ON CONFLICT(uuid, user_uuid) DO UPDATE SET updated_at = excluded.updated_at, \
                 name = excluded.name, atype = excluded.atype, push_token = excluded.push_token, \
                 refresh_token = excluded.refresh_token, twofactor_remember = excluded.twofactor_remember, \
                 push_uuid = excluded.push_uuid",
            )
            .bind(&[
                JsValue::from_str(&self.uuid),
                JsValue::from_str(&self.created_at),
                JsValue::from_str(&self.updated_at),
                JsValue::from_str(&self.user_uuid),
                JsValue::from_str(&self.name),
                JsValue::from_f64(self.atype as f64),
                opt_str(&self.push_token),
                JsValue::from_str(&self.refresh_token),
                opt_str(&self.twofactor_remember),
                opt_str(&self.push_uuid),
            ])?;
        let _result = stmt.run().await?;
        Ok(())
    }

    pub async fn delete(self, db: &D1Database) -> DbResult<()> {
        let stmt = db
            .prepare("DELETE FROM devices WHERE uuid = ?1 AND user_uuid = ?2")
            .bind(&[JsValue::from_str(&self.uuid), JsValue::from_str(&self.user_uuid)])?;
        let _result = stmt.run().await?;
        Ok(())
    }
}

fn format_date(dt: &NaiveDateTime) -> String {
    dt.and_utc().to_rfc3339_opts(chrono::SecondsFormat::Micros, true)
}

fn opt_str(value: &Option<String>) -> JsValue {
    match value {
        Some(s) => JsValue::from_str(s),
        None => JsValue::NULL,
    }
}
