use chrono::{NaiveDateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use worker::{D1Database, wasm_bindgen::JsValue};

use crate::db::DbResult;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Group {
    pub uuid: String,
    pub organizations_uuid: String,
    pub name: String,
    pub access_all: i32,
    pub external_id: Option<String>,
    pub creation_date: String,
    pub revision_date: String,
}

impl Group {
    pub fn new(organizations_uuid: String, name: String, access_all: bool) -> Self {
        let now = format_date(&Utc::now().naive_utc());
        Self {
            uuid: Uuid::new_v4().to_string(),
            organizations_uuid,
            name,
            access_all: if access_all { 1 } else { 0 },
            external_id: None,
            creation_date: now.clone(),
            revision_date: now,
        }
    }

    pub async fn find_by_uuid(db: &D1Database, uuid: &str) -> DbResult<Option<Self>> {
        let stmt =
            db.prepare("SELECT * FROM groups WHERE uuid = ?1").bind(&[JsValue::from_str(uuid)])?;
        Ok(stmt.first::<Self>(None).await?)
    }

    pub async fn find_by_org(db: &D1Database, organizations_uuid: &str) -> DbResult<Vec<Self>> {
        let stmt = db
            .prepare("SELECT * FROM groups WHERE organizations_uuid = ?1")
            .bind(&[JsValue::from_str(organizations_uuid)])?;
        Ok(stmt.all().await?.results::<Self>()?)
    }

    pub async fn save(&mut self, db: &D1Database) -> DbResult<()> {
        self.revision_date = format_date(&Utc::now().naive_utc());
        let stmt = db
            .prepare(
                "INSERT INTO groups (uuid, organizations_uuid, name, access_all, external_id, \
                 creation_date, revision_date) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7) \
                 ON CONFLICT(uuid) DO UPDATE SET \
                 organizations_uuid = excluded.organizations_uuid, name = excluded.name, \
                 access_all = excluded.access_all, external_id = excluded.external_id, \
                 revision_date = excluded.revision_date",
            )
            .bind(&[
                JsValue::from_str(&self.uuid),
                JsValue::from_str(&self.organizations_uuid),
                JsValue::from_str(&self.name),
                JsValue::from_f64(self.access_all as f64),
                opt_str(&self.external_id),
                JsValue::from_str(&self.creation_date),
                JsValue::from_str(&self.revision_date),
            ])?;
        let _result = stmt.run().await?;
        Ok(())
    }

    pub async fn delete(self, db: &D1Database) -> DbResult<()> {
        let stmt =
            db.prepare("DELETE FROM groups WHERE uuid = ?1").bind(&[JsValue::from_str(&self.uuid)])?;
        let _result = stmt.run().await?;
        Ok(())
    }
}

/// Junction table: `groups_users` — no struct fields.
pub struct GroupUser;

impl GroupUser {
    pub async fn set(
        db: &D1Database,
        groups_uuid: &str,
        users_organizations_uuid: &str,
    ) -> DbResult<()> {
        let stmt = db
            .prepare(
                "INSERT INTO groups_users (groups_uuid, users_organizations_uuid) \
                 VALUES (?1, ?2) ON CONFLICT(groups_uuid, users_organizations_uuid) DO NOTHING",
            )
            .bind(&[
                JsValue::from_str(groups_uuid),
                JsValue::from_str(users_organizations_uuid),
            ])?;
        let _result = stmt.run().await?;
        Ok(())
    }

    pub async fn unset(
        db: &D1Database,
        groups_uuid: &str,
        users_organizations_uuid: &str,
    ) -> DbResult<()> {
        let stmt = db
            .prepare(
                "DELETE FROM groups_users WHERE groups_uuid = ?1 AND users_organizations_uuid = ?2",
            )
            .bind(&[
                JsValue::from_str(groups_uuid),
                JsValue::from_str(users_organizations_uuid),
            ])?;
        let _result = stmt.run().await?;
        Ok(())
    }

    pub async fn list_by_group(
        db: &D1Database,
        groups_uuid: &str,
    ) -> DbResult<Vec<String>> {
        let stmt = db
            .prepare(
                "SELECT users_organizations_uuid FROM groups_users WHERE groups_uuid = ?1",
            )
            .bind(&[JsValue::from_str(groups_uuid)])?;
        #[derive(serde::Deserialize)]
        struct Row {
            users_organizations_uuid: String,
        }
        Ok(stmt.all().await?.results::<Row>()?.into_iter().map(|r| r.users_organizations_uuid).collect())
    }

    pub async fn list_by_member(
        db: &D1Database,
        users_organizations_uuid: &str,
    ) -> DbResult<Vec<String>> {
        let stmt = db
            .prepare(
                "SELECT groups_uuid FROM groups_users WHERE users_organizations_uuid = ?1",
            )
            .bind(&[JsValue::from_str(users_organizations_uuid)])?;
        #[derive(serde::Deserialize)]
        struct Row {
            groups_uuid: String,
        }
        Ok(stmt.all().await?.results::<Row>()?.into_iter().map(|r| r.groups_uuid).collect())
    }
}

/// Row in `collections_groups` — has extra permission fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollectionGroup {
    pub collections_uuid: String,
    pub groups_uuid: String,
    pub read_only: i32,
    pub hide_passwords: i32,
    pub manage: i32,
}

impl CollectionGroup {
    pub fn new(
        collections_uuid: String,
        groups_uuid: String,
        read_only: bool,
        hide_passwords: bool,
        manage: bool,
    ) -> Self {
        Self {
            collections_uuid,
            groups_uuid,
            read_only: if read_only { 1 } else { 0 },
            hide_passwords: if hide_passwords { 1 } else { 0 },
            manage: if manage { 1 } else { 0 },
        }
    }

    pub async fn find_by_collection(
        db: &D1Database,
        collections_uuid: &str,
    ) -> DbResult<Vec<Self>> {
        let stmt = db
            .prepare("SELECT * FROM collections_groups WHERE collections_uuid = ?1")
            .bind(&[JsValue::from_str(collections_uuid)])?;
        Ok(stmt.all().await?.results::<Self>()?)
    }

    pub async fn find_by_group(db: &D1Database, groups_uuid: &str) -> DbResult<Vec<Self>> {
        let stmt = db
            .prepare("SELECT * FROM collections_groups WHERE groups_uuid = ?1")
            .bind(&[JsValue::from_str(groups_uuid)])?;
        Ok(stmt.all().await?.results::<Self>()?)
    }

    pub async fn set(&self, db: &D1Database) -> DbResult<()> {
        let stmt = db
            .prepare(
                "INSERT INTO collections_groups \
                 (collections_uuid, groups_uuid, read_only, hide_passwords, manage) \
                 VALUES (?1, ?2, ?3, ?4, ?5) \
                 ON CONFLICT(collections_uuid, groups_uuid) DO UPDATE SET \
                 read_only = excluded.read_only, hide_passwords = excluded.hide_passwords, \
                 manage = excluded.manage",
            )
            .bind(&[
                JsValue::from_str(&self.collections_uuid),
                JsValue::from_str(&self.groups_uuid),
                JsValue::from_f64(self.read_only as f64),
                JsValue::from_f64(self.hide_passwords as f64),
                JsValue::from_f64(self.manage as f64),
            ])?;
        let _result = stmt.run().await?;
        Ok(())
    }

    pub async fn delete(self, db: &D1Database) -> DbResult<()> {
        let stmt = db
            .prepare(
                "DELETE FROM collections_groups WHERE collections_uuid = ?1 AND groups_uuid = ?2",
            )
            .bind(&[
                JsValue::from_str(&self.collections_uuid),
                JsValue::from_str(&self.groups_uuid),
            ])?;
        let _result = stmt.run().await?;
        Ok(())
    }

    pub async fn delete_all_by_collection(
        db: &D1Database,
        collections_uuid: &str,
    ) -> DbResult<()> {
        let stmt = db
            .prepare("DELETE FROM collections_groups WHERE collections_uuid = ?1")
            .bind(&[JsValue::from_str(collections_uuid)])?;
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
