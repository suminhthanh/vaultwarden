use chrono::{NaiveDateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use worker::{D1Database, wasm_bindgen::JsValue};

use crate::db::DbResult;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Cipher {
    pub uuid: String,
    pub created_at: String,
    pub updated_at: String,

    pub user_uuid: Option<String>,
    pub organization_uuid: Option<String>,

    #[serde(rename = "key")]
    pub key: Option<String>,

    pub atype: i32,
    pub name: String,
    pub notes: Option<String>,
    pub fields: Option<String>,

    pub data: String,

    pub password_history: Option<String>,
    pub deleted_at: Option<String>,
    pub reprompt: Option<i32>,
}

impl Cipher {
    pub fn new(atype: i32, name: String) -> Self {
        let now = format_date(&Utc::now().naive_utc());
        Self {
            uuid: Uuid::new_v4().to_string(),
            created_at: now.clone(),
            updated_at: now,
            user_uuid: None,
            organization_uuid: None,
            key: None,
            atype,
            name,
            notes: None,
            fields: None,
            data: String::new(),
            password_history: None,
            deleted_at: None,
            reprompt: None,
        }
    }

    pub async fn find_by_uuid(db: &D1Database, uuid: &str) -> DbResult<Option<Self>> {
        let stmt = db.prepare("SELECT * FROM ciphers WHERE uuid = ?1").bind(&[JsValue::from_str(uuid)])?;
        Ok(stmt.first::<Self>(None).await?)
    }

    pub async fn find_owned_by_user(db: &D1Database, user_uuid: &str) -> DbResult<Vec<Self>> {
        let stmt = db
            .prepare("SELECT * FROM ciphers WHERE user_uuid = ?1 AND organization_uuid IS NULL")
            .bind(&[JsValue::from_str(user_uuid)])?;
        Ok(stmt.all().await?.results::<Self>()?)
    }

    /// All ciphers visible to a user. A user sees:
    ///   1. Ciphers they personally own (organization_uuid IS NULL).
    ///   2. Org-owned ciphers when they're a member with access_all = 1.
    ///   3. Org-owned ciphers when they're a member assigned to the cipher's
    ///      collection — directly via `users_collections` or via a group ACL.
    pub async fn find_visible_to_user(db: &D1Database, user_uuid: &str) -> DbResult<Vec<Self>> {
        let stmt = db
            .prepare(
                "SELECT DISTINCT c.* FROM ciphers c \
                 LEFT JOIN users_organizations m \
                   ON c.organization_uuid = m.org_uuid AND m.user_uuid = ?1 \
                 LEFT JOIN ciphers_collections cc ON cc.cipher_uuid = c.uuid \
                 LEFT JOIN users_collections uc \
                   ON uc.collection_uuid = cc.collection_uuid AND uc.user_uuid = ?1 \
                 LEFT JOIN groups_users gu ON gu.users_organizations_uuid = m.uuid \
                 LEFT JOIN collections_groups cg \
                   ON cg.groups_uuid = gu.groups_uuid \
                  AND cg.collections_uuid = cc.collection_uuid \
                 WHERE c.user_uuid = ?1 \
                    OR m.access_all = 1 \
                    OR uc.user_uuid IS NOT NULL \
                    OR cg.groups_uuid IS NOT NULL",
            )
            .bind(&[JsValue::from_str(user_uuid)])?;
        Ok(stmt.all().await?.results::<Self>()?)
    }

    pub async fn find_by_org(db: &D1Database, org_uuid: &str) -> DbResult<Vec<Self>> {
        let stmt = db
            .prepare("SELECT * FROM ciphers WHERE organization_uuid = ?1")
            .bind(&[JsValue::from_str(org_uuid)])?;
        Ok(stmt.all().await?.results::<Self>()?)
    }

    pub async fn save(&mut self, db: &D1Database) -> DbResult<()> {
        self.updated_at = format_date(&Utc::now().naive_utc());

        let stmt = db
            .prepare(
                "INSERT INTO ciphers (\
                    uuid, created_at, updated_at, user_uuid, organization_uuid, \"key\", \
                    atype, name, notes, fields, data, password_history, deleted_at, reprompt\
                 ) VALUES (\
                    ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14\
                 ) ON CONFLICT(uuid) DO UPDATE SET \
                    updated_at = excluded.updated_at, user_uuid = excluded.user_uuid, \
                    organization_uuid = excluded.organization_uuid, \"key\" = excluded.\"key\", \
                    atype = excluded.atype, name = excluded.name, notes = excluded.notes, \
                    fields = excluded.fields, data = excluded.data, password_history = excluded.password_history, \
                    deleted_at = excluded.deleted_at, reprompt = excluded.reprompt",
            )
            .bind(&[
                JsValue::from_str(&self.uuid),
                JsValue::from_str(&self.created_at),
                JsValue::from_str(&self.updated_at),
                opt_str(&self.user_uuid),
                opt_str(&self.organization_uuid),
                opt_str(&self.key),
                JsValue::from_f64(self.atype as f64),
                JsValue::from_str(&self.name),
                opt_str(&self.notes),
                opt_str(&self.fields),
                JsValue::from_str(&self.data),
                opt_str(&self.password_history),
                opt_str(&self.deleted_at),
                opt_i32(self.reprompt),
            ])?;
        let _result = stmt.run().await?;
        Ok(())
    }

    pub async fn delete(self, db: &D1Database) -> DbResult<()> {
        let stmt = db.prepare("DELETE FROM ciphers WHERE uuid = ?1").bind(&[JsValue::from_str(&self.uuid)])?;
        let _result = stmt.run().await?;
        Ok(())
    }

    /// Hard-delete every cipher whose `deleted_at` is older than `before_iso`.
    /// Returns the number of rows removed.
    pub async fn purge_trashed_before(db: &D1Database, before_iso: &str) -> DbResult<i64> {
        let stmt = db
            .prepare("DELETE FROM ciphers WHERE deleted_at IS NOT NULL AND deleted_at < ?1")
            .bind(&[JsValue::from_str(before_iso)])?;
        let result = stmt.run().await?;
        Ok(result
            .meta()?
            .and_then(|m| m.rows_written.map(|v| v as i64))
            .unwrap_or(0))
    }

    /// `(cipher_uuid, attachment_id)` pairs for ciphers whose `deleted_at`
    /// is older than `before_iso`. Used by the cron to wipe R2 objects
    /// before the row-level purge runs.
    pub async fn trashed_attachment_keys(
        db: &D1Database,
        before_iso: &str,
    ) -> DbResult<Vec<(String, String)>> {
        #[derive(serde::Deserialize)]
        struct Row {
            cipher_uuid: String,
            attachment_id: String,
        }
        let stmt = db
            .prepare(
                "SELECT a.cipher_uuid AS cipher_uuid, a.id AS attachment_id \
                 FROM attachments a \
                 JOIN ciphers c ON c.uuid = a.cipher_uuid \
                 WHERE c.deleted_at IS NOT NULL AND c.deleted_at < ?1",
            )
            .bind(&[JsValue::from_str(before_iso)])?;
        Ok(stmt
            .all()
            .await?
            .results::<Row>()?
            .into_iter()
            .map(|r| (r.cipher_uuid, r.attachment_id))
            .collect())
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
