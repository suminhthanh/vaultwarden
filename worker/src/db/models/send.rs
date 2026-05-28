use chrono::{NaiveDateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use worker::{D1Database, wasm_bindgen::JsValue};

use crate::db::DbResult;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Send {
    pub uuid: String,
    pub user_uuid: Option<String>,
    pub organization_uuid: Option<String>,
    pub name: String,
    pub notes: Option<String>,
    pub atype: i32,
    pub data: String,
    pub akey: String,
    #[serde(default, skip_deserializing)]
    pub password_hash: Vec<u8>,
    #[serde(default, skip_deserializing)]
    pub password_salt: Vec<u8>,
    pub password_iter: Option<i32>,
    pub max_access_count: Option<i32>,
    pub access_count: i32,
    pub creation_date: String,
    pub revision_date: String,
    pub expiration_date: Option<String>,
    pub deletion_date: String,
    pub disabled: i32,
    pub hide_email: Option<i32>,
}

impl Send {
    pub fn new(atype: i32, name: String, data: String, akey: String, deletion_date: String) -> Self {
        let now = format_date(&Utc::now().naive_utc());
        Self {
            uuid: Uuid::new_v4().to_string(),
            user_uuid: None,
            organization_uuid: None,
            name,
            notes: None,
            atype,
            data,
            akey,
            password_hash: vec![],
            password_salt: vec![],
            password_iter: None,
            max_access_count: None,
            access_count: 0,
            creation_date: now.clone(),
            revision_date: now,
            expiration_date: None,
            deletion_date,
            disabled: 0,
            hide_email: None,
        }
    }

    pub async fn find_by_uuid(db: &D1Database, uuid: &str) -> DbResult<Option<Self>> {
        let stmt = db
            .prepare(
                "SELECT uuid, user_uuid, organization_uuid, name, notes, atype, data, akey, \
                 password_iter, max_access_count, access_count, creation_date, revision_date, \
                 expiration_date, deletion_date, disabled, hide_email FROM sends WHERE uuid = ?1",
            )
            .bind(&[JsValue::from_str(uuid)])?;
        Ok(stmt.first::<Self>(None).await?)
    }

    pub async fn find_by_user(db: &D1Database, user_uuid: &str) -> DbResult<Vec<Self>> {
        let stmt = db
            .prepare(
                "SELECT uuid, user_uuid, organization_uuid, name, notes, atype, data, akey, \
                 password_iter, max_access_count, access_count, creation_date, revision_date, \
                 expiration_date, deletion_date, disabled, hide_email FROM sends WHERE user_uuid = ?1",
            )
            .bind(&[JsValue::from_str(user_uuid)])?;
        Ok(stmt.all().await?.results::<Self>()?)
    }

    pub async fn save(&mut self, db: &D1Database) -> DbResult<()> {
        self.revision_date = format_date(&Utc::now().naive_utc());
        let stmt = db
            .prepare(
                "INSERT INTO sends (uuid, user_uuid, organization_uuid, name, notes, atype, data, akey, \
                 password_iter, max_access_count, access_count, creation_date, revision_date, \
                 expiration_date, deletion_date, disabled, hide_email) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17) \
                 ON CONFLICT(uuid) DO UPDATE SET \
                 user_uuid = excluded.user_uuid, organization_uuid = excluded.organization_uuid, \
                 name = excluded.name, notes = excluded.notes, atype = excluded.atype, \
                 data = excluded.data, akey = excluded.akey, \
                 password_iter = excluded.password_iter, max_access_count = excluded.max_access_count, \
                 access_count = excluded.access_count, revision_date = excluded.revision_date, \
                 expiration_date = excluded.expiration_date, deletion_date = excluded.deletion_date, \
                 disabled = excluded.disabled, hide_email = excluded.hide_email",
            )
            .bind(&[
                JsValue::from_str(&self.uuid),
                opt_str(&self.user_uuid),
                opt_str(&self.organization_uuid),
                JsValue::from_str(&self.name),
                opt_str(&self.notes),
                JsValue::from_f64(self.atype as f64),
                JsValue::from_str(&self.data),
                JsValue::from_str(&self.akey),
                opt_i32(self.password_iter),
                opt_i32(self.max_access_count),
                JsValue::from_f64(self.access_count as f64),
                JsValue::from_str(&self.creation_date),
                JsValue::from_str(&self.revision_date),
                opt_str(&self.expiration_date),
                JsValue::from_str(&self.deletion_date),
                JsValue::from_f64(self.disabled as f64),
                opt_i32(self.hide_email),
            ])?;
        let _result = stmt.run().await?;
        Ok(())
    }

    pub async fn delete(self, db: &D1Database) -> DbResult<()> {
        let stmt =
            db.prepare("DELETE FROM sends WHERE uuid = ?1").bind(&[JsValue::from_str(&self.uuid)])?;
        let _result = stmt.run().await?;
        Ok(())
    }

    /// Hard-delete every send whose `deletion_date` has passed.
    /// Returns the number of rows removed.
    pub async fn purge_expired(db: &D1Database, now_iso: &str) -> DbResult<i64> {
        let stmt = db
            .prepare("DELETE FROM sends WHERE deletion_date <= ?1")
            .bind(&[JsValue::from_str(now_iso)])?;
        let result = stmt.run().await?;
        Ok(result
            .meta()?
            .and_then(|m| m.rows_written.map(|v| v as i64))
            .unwrap_or(0))
    }

    /// Find UUIDs of file sends (`atype = 1`) whose deletion_date has passed.
    /// Used by the cron to clear R2 objects before the row-level purge.
    pub async fn expired_file_send_uuids(db: &D1Database, now_iso: &str) -> DbResult<Vec<String>> {
        #[derive(serde::Deserialize)]
        struct Row {
            uuid: String,
        }
        let stmt = db
            .prepare("SELECT uuid FROM sends WHERE atype = 1 AND deletion_date <= ?1")
            .bind(&[JsValue::from_str(now_iso)])?;
        let rows: Vec<Row> = stmt.all().await?.results::<Row>()?;
        Ok(rows.into_iter().map(|r| r.uuid).collect())
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
