use chrono::{NaiveDateTime, Utc};
use serde::{Deserialize, Serialize};
use worker::{D1Database, wasm_bindgen::JsValue};

use crate::db::DbResult;

/// `twofactor_incomplete` has a composite primary key `(user_uuid, device_uuid)`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TwoFactorIncomplete {
    pub user_uuid: String,
    pub device_uuid: String,
    pub device_name: String,
    pub login_time: String,
    pub ip_address: String,
    pub device_type: i32,
}

impl TwoFactorIncomplete {
    pub fn new(
        user_uuid: String,
        device_uuid: String,
        device_name: String,
        ip_address: String,
        device_type: i32,
    ) -> Self {
        Self {
            user_uuid,
            device_uuid,
            device_name,
            login_time: format_date(&Utc::now().naive_utc()),
            ip_address,
            device_type,
        }
    }

    pub async fn find(
        db: &D1Database,
        user_uuid: &str,
        device_uuid: &str,
    ) -> DbResult<Option<Self>> {
        let stmt = db
            .prepare(
                "SELECT * FROM twofactor_incomplete WHERE user_uuid = ?1 AND device_uuid = ?2",
            )
            .bind(&[JsValue::from_str(user_uuid), JsValue::from_str(device_uuid)])?;
        Ok(stmt.first::<Self>(None).await?)
    }

    pub async fn find_by_user(db: &D1Database, user_uuid: &str) -> DbResult<Vec<Self>> {
        let stmt = db
            .prepare("SELECT * FROM twofactor_incomplete WHERE user_uuid = ?1")
            .bind(&[JsValue::from_str(user_uuid)])?;
        Ok(stmt.all().await?.results::<Self>()?)
    }

    pub async fn save(&self, db: &D1Database) -> DbResult<()> {
        let stmt = db
            .prepare(
                "INSERT INTO twofactor_incomplete \
                 (user_uuid, device_uuid, device_name, login_time, ip_address, device_type) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6) \
                 ON CONFLICT(user_uuid, device_uuid) DO UPDATE SET \
                 device_name = excluded.device_name, login_time = excluded.login_time, \
                 ip_address = excluded.ip_address, device_type = excluded.device_type",
            )
            .bind(&[
                JsValue::from_str(&self.user_uuid),
                JsValue::from_str(&self.device_uuid),
                JsValue::from_str(&self.device_name),
                JsValue::from_str(&self.login_time),
                JsValue::from_str(&self.ip_address),
                JsValue::from_f64(self.device_type as f64),
            ])?;
        let _result = stmt.run().await?;
        Ok(())
    }

    pub async fn delete(self, db: &D1Database) -> DbResult<()> {
        let stmt = db
            .prepare(
                "DELETE FROM twofactor_incomplete WHERE user_uuid = ?1 AND device_uuid = ?2",
            )
            .bind(&[JsValue::from_str(&self.user_uuid), JsValue::from_str(&self.device_uuid)])?;
        let _result = stmt.run().await?;
        Ok(())
    }
}

fn format_date(dt: &NaiveDateTime) -> String {
    dt.and_utc().to_rfc3339_opts(chrono::SecondsFormat::Micros, true)
}
