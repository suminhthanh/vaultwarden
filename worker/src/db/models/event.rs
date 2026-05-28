use chrono::{NaiveDateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use worker::{D1Database, wasm_bindgen::JsValue};

use crate::db::DbResult;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    pub uuid: String,
    pub event_type: i32,
    pub user_uuid: Option<String>,
    pub org_uuid: Option<String>,
    pub cipher_uuid: Option<String>,
    pub collection_uuid: Option<String>,
    pub group_uuid: Option<String>,
    pub org_user_uuid: Option<String>,
    pub act_user_uuid: Option<String>,
    pub device_type: Option<i32>,
    pub ip_address: Option<String>,
    pub event_date: String,
    pub policy_uuid: Option<String>,
    pub provider_uuid: Option<String>,
    pub provider_user_uuid: Option<String>,
    pub provider_org_uuid: Option<String>,
}

impl Event {
    pub fn new(event_type: i32) -> Self {
        Self {
            uuid: Uuid::new_v4().to_string(),
            event_type,
            user_uuid: None,
            org_uuid: None,
            cipher_uuid: None,
            collection_uuid: None,
            group_uuid: None,
            org_user_uuid: None,
            act_user_uuid: None,
            device_type: None,
            ip_address: None,
            event_date: format_date(&Utc::now().naive_utc()),
            policy_uuid: None,
            provider_uuid: None,
            provider_user_uuid: None,
            provider_org_uuid: None,
        }
    }

    pub async fn find_by_uuid(db: &D1Database, uuid: &str) -> DbResult<Option<Self>> {
        let stmt =
            db.prepare("SELECT * FROM event WHERE uuid = ?1").bind(&[JsValue::from_str(uuid)])?;
        Ok(stmt.first::<Self>(None).await?)
    }

    pub async fn find_by_org(db: &D1Database, org_uuid: &str) -> DbResult<Vec<Self>> {
        let stmt = db
            .prepare("SELECT * FROM event WHERE org_uuid = ?1 ORDER BY event_date DESC")
            .bind(&[JsValue::from_str(org_uuid)])?;
        Ok(stmt.all().await?.results::<Self>()?)
    }

    pub async fn find_by_org_in_range(
        db: &D1Database,
        org_uuid: &str,
        start: &str,
        end: &str,
    ) -> DbResult<Vec<Self>> {
        let stmt = db
            .prepare(
                "SELECT * FROM event WHERE org_uuid = ?1 \
                 AND event_date >= ?2 AND event_date < ?3 \
                 ORDER BY event_date DESC LIMIT 1000",
            )
            .bind(&[
                JsValue::from_str(org_uuid),
                JsValue::from_str(start),
                JsValue::from_str(end),
            ])?;
        Ok(stmt.all().await?.results::<Self>()?)
    }

    pub async fn find_by_user_in_range(
        db: &D1Database,
        user_uuid: &str,
        start: &str,
        end: &str,
    ) -> DbResult<Vec<Self>> {
        let stmt = db
            .prepare(
                "SELECT * FROM event WHERE user_uuid = ?1 \
                 AND event_date >= ?2 AND event_date < ?3 \
                 ORDER BY event_date DESC LIMIT 1000",
            )
            .bind(&[
                JsValue::from_str(user_uuid),
                JsValue::from_str(start),
                JsValue::from_str(end),
            ])?;
        Ok(stmt.all().await?.results::<Self>()?)
    }

    pub async fn find_by_cipher_in_range(
        db: &D1Database,
        cipher_uuid: &str,
        start: &str,
        end: &str,
    ) -> DbResult<Vec<Self>> {
        let stmt = db
            .prepare(
                "SELECT * FROM event WHERE cipher_uuid = ?1 \
                 AND event_date >= ?2 AND event_date < ?3 \
                 ORDER BY event_date DESC LIMIT 1000",
            )
            .bind(&[
                JsValue::from_str(cipher_uuid),
                JsValue::from_str(start),
                JsValue::from_str(end),
            ])?;
        Ok(stmt.all().await?.results::<Self>()?)
    }

    pub async fn find_by_user(db: &D1Database, user_uuid: &str) -> DbResult<Vec<Self>> {
        let stmt = db
            .prepare("SELECT * FROM event WHERE user_uuid = ?1 ORDER BY event_date DESC")
            .bind(&[JsValue::from_str(user_uuid)])?;
        Ok(stmt.all().await?.results::<Self>()?)
    }

    pub async fn find_by_cipher(db: &D1Database, cipher_uuid: &str) -> DbResult<Vec<Self>> {
        let stmt = db
            .prepare("SELECT * FROM event WHERE cipher_uuid = ?1 ORDER BY event_date DESC")
            .bind(&[JsValue::from_str(cipher_uuid)])?;
        Ok(stmt.all().await?.results::<Self>()?)
    }

    pub async fn save(&self, db: &D1Database) -> DbResult<()> {
        let stmt = db
            .prepare(
                "INSERT INTO event (uuid, event_type, user_uuid, org_uuid, cipher_uuid, \
                 collection_uuid, group_uuid, org_user_uuid, act_user_uuid, device_type, \
                 ip_address, event_date, policy_uuid, provider_uuid, provider_user_uuid, \
                 provider_org_uuid) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16) \
                 ON CONFLICT(uuid) DO UPDATE SET \
                 event_type = excluded.event_type, user_uuid = excluded.user_uuid, \
                 org_uuid = excluded.org_uuid, cipher_uuid = excluded.cipher_uuid, \
                 collection_uuid = excluded.collection_uuid, group_uuid = excluded.group_uuid, \
                 org_user_uuid = excluded.org_user_uuid, act_user_uuid = excluded.act_user_uuid, \
                 device_type = excluded.device_type, ip_address = excluded.ip_address, \
                 event_date = excluded.event_date, policy_uuid = excluded.policy_uuid, \
                 provider_uuid = excluded.provider_uuid, \
                 provider_user_uuid = excluded.provider_user_uuid, \
                 provider_org_uuid = excluded.provider_org_uuid",
            )
            .bind(&[
                JsValue::from_str(&self.uuid),
                JsValue::from_f64(self.event_type as f64),
                opt_str(&self.user_uuid),
                opt_str(&self.org_uuid),
                opt_str(&self.cipher_uuid),
                opt_str(&self.collection_uuid),
                opt_str(&self.group_uuid),
                opt_str(&self.org_user_uuid),
                opt_str(&self.act_user_uuid),
                opt_i32(self.device_type),
                opt_str(&self.ip_address),
                JsValue::from_str(&self.event_date),
                opt_str(&self.policy_uuid),
                opt_str(&self.provider_uuid),
                opt_str(&self.provider_user_uuid),
                opt_str(&self.provider_org_uuid),
            ])?;
        let _result = stmt.run().await?;
        Ok(())
    }

    pub async fn delete(self, db: &D1Database) -> DbResult<()> {
        let stmt =
            db.prepare("DELETE FROM event WHERE uuid = ?1").bind(&[JsValue::from_str(&self.uuid)])?;
        let _result = stmt.run().await?;
        Ok(())
    }

    /// Delete all events with `event_date < before` (RFC3339 string).
    pub async fn delete_old(db: &D1Database, before: &str) -> DbResult<()> {
        let stmt = db
            .prepare("DELETE FROM event WHERE event_date < ?1")
            .bind(&[JsValue::from_str(before)])?;
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

fn opt_i32(value: Option<i32>) -> JsValue {
    match value {
        Some(v) => JsValue::from_f64(v as f64),
        None => JsValue::NULL,
    }
}
