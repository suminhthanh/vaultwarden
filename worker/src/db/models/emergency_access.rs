use chrono::{NaiveDateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use worker::{D1Database, wasm_bindgen::JsValue};

use crate::db::DbResult;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmergencyAccess {
    pub uuid: String,
    pub grantor_uuid: Option<String>,
    pub grantee_uuid: Option<String>,
    pub email: Option<String>,
    pub key_encrypted: Option<String>,
    pub atype: i32,
    pub status: i32,
    pub wait_time_days: i32,
    pub recovery_initiated_at: Option<String>,
    pub last_notification_at: Option<String>,
    pub updated_at: String,
    pub created_at: String,
}

impl EmergencyAccess {
    pub fn new(atype: i32, status: i32, wait_time_days: i32) -> Self {
        let now = format_date(&Utc::now().naive_utc());
        Self {
            uuid: Uuid::new_v4().to_string(),
            grantor_uuid: None,
            grantee_uuid: None,
            email: None,
            key_encrypted: None,
            atype,
            status,
            wait_time_days,
            recovery_initiated_at: None,
            last_notification_at: None,
            updated_at: now.clone(),
            created_at: now,
        }
    }

    pub async fn find_by_uuid(db: &D1Database, uuid: &str) -> DbResult<Option<Self>> {
        let stmt = db
            .prepare("SELECT * FROM emergency_access WHERE uuid = ?1")
            .bind(&[JsValue::from_str(uuid)])?;
        Ok(stmt.first::<Self>(None).await?)
    }

    pub async fn find_by_grantor(db: &D1Database, grantor_uuid: &str) -> DbResult<Vec<Self>> {
        let stmt = db
            .prepare("SELECT * FROM emergency_access WHERE grantor_uuid = ?1")
            .bind(&[JsValue::from_str(grantor_uuid)])?;
        Ok(stmt.all().await?.results::<Self>()?)
    }

    pub async fn find_by_grantee(db: &D1Database, grantee_uuid: &str) -> DbResult<Vec<Self>> {
        let stmt = db
            .prepare("SELECT * FROM emergency_access WHERE grantee_uuid = ?1")
            .bind(&[JsValue::from_str(grantee_uuid)])?;
        Ok(stmt.all().await?.results::<Self>()?)
    }

    pub async fn save(&mut self, db: &D1Database) -> DbResult<()> {
        self.updated_at = format_date(&Utc::now().naive_utc());
        let stmt = db
            .prepare(
                "INSERT INTO emergency_access (uuid, grantor_uuid, grantee_uuid, email, \
                 key_encrypted, atype, status, wait_time_days, recovery_initiated_at, \
                 last_notification_at, updated_at, created_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12) \
                 ON CONFLICT(uuid) DO UPDATE SET \
                 grantor_uuid = excluded.grantor_uuid, grantee_uuid = excluded.grantee_uuid, \
                 email = excluded.email, key_encrypted = excluded.key_encrypted, \
                 atype = excluded.atype, status = excluded.status, \
                 wait_time_days = excluded.wait_time_days, \
                 recovery_initiated_at = excluded.recovery_initiated_at, \
                 last_notification_at = excluded.last_notification_at, \
                 updated_at = excluded.updated_at",
            )
            .bind(&[
                JsValue::from_str(&self.uuid),
                opt_str(&self.grantor_uuid),
                opt_str(&self.grantee_uuid),
                opt_str(&self.email),
                opt_str(&self.key_encrypted),
                JsValue::from_f64(self.atype as f64),
                JsValue::from_f64(self.status as f64),
                JsValue::from_f64(self.wait_time_days as f64),
                opt_str(&self.recovery_initiated_at),
                opt_str(&self.last_notification_at),
                JsValue::from_str(&self.updated_at),
                JsValue::from_str(&self.created_at),
            ])?;
        let _result = stmt.run().await?;
        Ok(())
    }

    pub async fn delete(self, db: &D1Database) -> DbResult<()> {
        let stmt = db
            .prepare("DELETE FROM emergency_access WHERE uuid = ?1")
            .bind(&[JsValue::from_str(&self.uuid)])?;
        let _result = stmt.run().await?;
        Ok(())
    }

    /// Approve any RecoveryInitiated rows whose wait window has elapsed.
    /// Mirrors upstream's `emergency_request_timeout_job`. Returns the number
    /// of rows transitioned to RecoveryApproved (4).
    pub async fn auto_approve_due(db: &D1Database) -> DbResult<i64> {
        let stmt = db.prepare(
            "UPDATE emergency_access \
             SET status = 4, updated_at = ?1 \
             WHERE status = 3 \
               AND recovery_initiated_at IS NOT NULL \
               AND datetime(recovery_initiated_at, '+' || wait_time_days || ' days') <= ?1",
        ).bind(&[JsValue::from_str(&format_date(&Utc::now().naive_utc()))])?;
        let result = stmt.run().await?;
        Ok(result
            .meta()?
            .and_then(|m| m.rows_written.map(|v| v as i64))
            .unwrap_or(0))
    }

    /// Find recovery requests waiting on a reminder (15 minutes since last
    /// notification). Returns rows the cron should email about.
    pub async fn pending_reminders(db: &D1Database) -> DbResult<Vec<Self>> {
        let now = format_date(&Utc::now().naive_utc());
        let stmt = db
            .prepare(
                "SELECT * FROM emergency_access \
                 WHERE status = 3 \
                   AND recovery_initiated_at IS NOT NULL \
                   AND (last_notification_at IS NULL \
                        OR datetime(last_notification_at, '+15 minutes') <= ?1)",
            )
            .bind(&[JsValue::from_str(&now)])?;
        Ok(stmt.all().await?.results::<Self>()?)
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
