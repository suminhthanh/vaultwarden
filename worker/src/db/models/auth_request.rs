use chrono::{NaiveDateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use worker::{D1Database, wasm_bindgen::JsValue};

use crate::db::DbResult;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthRequest {
    pub uuid: String,
    pub user_uuid: String,
    pub organization_uuid: Option<String>,
    pub request_device_identifier: String,
    pub device_type: i32,
    pub request_ip: String,
    pub response_device_id: Option<String>,
    pub access_code: String,
    pub public_key: String,
    pub enc_key: Option<String>,
    pub master_password_hash: Option<String>,
    pub approved: Option<i32>,
    pub creation_date: String,
    pub response_date: Option<String>,
    pub authentication_date: Option<String>,
}

impl AuthRequest {
    pub fn new(
        user_uuid: String,
        request_device_identifier: String,
        device_type: i32,
        request_ip: String,
        access_code: String,
        public_key: String,
    ) -> Self {
        Self {
            uuid: Uuid::new_v4().to_string(),
            user_uuid,
            organization_uuid: None,
            request_device_identifier,
            device_type,
            request_ip,
            response_device_id: None,
            access_code,
            public_key,
            enc_key: None,
            master_password_hash: None,
            approved: None,
            creation_date: format_date(&Utc::now().naive_utc()),
            response_date: None,
            authentication_date: None,
        }
    }

    pub async fn find_by_uuid(db: &D1Database, uuid: &str) -> DbResult<Option<Self>> {
        let stmt = db
            .prepare("SELECT * FROM auth_requests WHERE uuid = ?1")
            .bind(&[JsValue::from_str(uuid)])?;
        Ok(stmt.first::<Self>(None).await?)
    }

    pub async fn find_by_user(db: &D1Database, user_uuid: &str) -> DbResult<Vec<Self>> {
        let stmt = db
            .prepare("SELECT * FROM auth_requests WHERE user_uuid = ?1")
            .bind(&[JsValue::from_str(user_uuid)])?;
        Ok(stmt.all().await?.results::<Self>()?)
    }

    pub async fn save(&self, db: &D1Database) -> DbResult<()> {
        let stmt = db
            .prepare(
                "INSERT INTO auth_requests (uuid, user_uuid, organization_uuid, \
                 request_device_identifier, device_type, request_ip, response_device_id, \
                 access_code, public_key, enc_key, master_password_hash, approved, \
                 creation_date, response_date, authentication_date) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15) \
                 ON CONFLICT(uuid) DO UPDATE SET \
                 user_uuid = excluded.user_uuid, \
                 organization_uuid = excluded.organization_uuid, \
                 request_device_identifier = excluded.request_device_identifier, \
                 device_type = excluded.device_type, request_ip = excluded.request_ip, \
                 response_device_id = excluded.response_device_id, \
                 access_code = excluded.access_code, public_key = excluded.public_key, \
                 enc_key = excluded.enc_key, \
                 master_password_hash = excluded.master_password_hash, \
                 approved = excluded.approved, response_date = excluded.response_date, \
                 authentication_date = excluded.authentication_date",
            )
            .bind(&[
                JsValue::from_str(&self.uuid),
                JsValue::from_str(&self.user_uuid),
                opt_str(&self.organization_uuid),
                JsValue::from_str(&self.request_device_identifier),
                JsValue::from_f64(self.device_type as f64),
                JsValue::from_str(&self.request_ip),
                opt_str(&self.response_device_id),
                JsValue::from_str(&self.access_code),
                JsValue::from_str(&self.public_key),
                opt_str(&self.enc_key),
                opt_str(&self.master_password_hash),
                opt_i32(self.approved),
                JsValue::from_str(&self.creation_date),
                opt_str(&self.response_date),
                opt_str(&self.authentication_date),
            ])?;
        let _result = stmt.run().await?;
        Ok(())
    }

    pub async fn delete(self, db: &D1Database) -> DbResult<()> {
        let stmt = db
            .prepare("DELETE FROM auth_requests WHERE uuid = ?1")
            .bind(&[JsValue::from_str(&self.uuid)])?;
        let _result = stmt.run().await?;
        Ok(())
    }

    /// Delete all requests with `creation_date < before` (RFC3339 string).
    pub async fn purge_old(db: &D1Database, before: &str) -> DbResult<()> {
        let stmt = db
            .prepare("DELETE FROM auth_requests WHERE creation_date < ?1")
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
