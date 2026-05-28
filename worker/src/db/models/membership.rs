use serde::{Deserialize, Serialize};
use uuid::Uuid;
use worker::{D1Database, wasm_bindgen::JsValue};

use crate::db::DbResult;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Membership {
    pub uuid: String,
    pub user_uuid: String,
    pub org_uuid: String,
    pub access_all: i32,
    pub akey: String,
    pub status: i32,
    pub atype: i32,
    pub reset_password_key: Option<String>,
    pub external_id: Option<String>,
    pub invited_by_email: Option<String>,
}

impl Membership {
    pub fn new(user_uuid: String, org_uuid: String, akey: String, atype: i32, status: i32) -> Self {
        Self {
            uuid: Uuid::new_v4().to_string(),
            user_uuid,
            org_uuid,
            access_all: 0,
            akey,
            status,
            atype,
            reset_password_key: None,
            external_id: None,
            invited_by_email: None,
        }
    }

    pub async fn find_by_uuid(db: &D1Database, uuid: &str) -> DbResult<Option<Self>> {
        let stmt = db
            .prepare("SELECT * FROM users_organizations WHERE uuid = ?1")
            .bind(&[JsValue::from_str(uuid)])?;
        Ok(stmt.first::<Self>(None).await?)
    }

    pub async fn find_by_user_and_org(
        db: &D1Database,
        user_uuid: &str,
        org_uuid: &str,
    ) -> DbResult<Option<Self>> {
        let stmt = db
            .prepare(
                "SELECT * FROM users_organizations WHERE user_uuid = ?1 AND org_uuid = ?2",
            )
            .bind(&[JsValue::from_str(user_uuid), JsValue::from_str(org_uuid)])?;
        Ok(stmt.first::<Self>(None).await?)
    }

    pub async fn find_by_user(db: &D1Database, user_uuid: &str) -> DbResult<Vec<Self>> {
        let stmt = db
            .prepare("SELECT * FROM users_organizations WHERE user_uuid = ?1")
            .bind(&[JsValue::from_str(user_uuid)])?;
        Ok(stmt.all().await?.results::<Self>()?)
    }

    pub async fn find_by_org(db: &D1Database, org_uuid: &str) -> DbResult<Vec<Self>> {
        let stmt = db
            .prepare("SELECT * FROM users_organizations WHERE org_uuid = ?1")
            .bind(&[JsValue::from_str(org_uuid)])?;
        Ok(stmt.all().await?.results::<Self>()?)
    }

    pub async fn save(&self, db: &D1Database) -> DbResult<()> {
        let stmt = db
            .prepare(
                "INSERT INTO users_organizations \
                 (uuid, user_uuid, org_uuid, access_all, akey, status, atype, \
                 reset_password_key, external_id, invited_by_email) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10) \
                 ON CONFLICT(uuid) DO UPDATE SET \
                 user_uuid = excluded.user_uuid, org_uuid = excluded.org_uuid, \
                 access_all = excluded.access_all, akey = excluded.akey, \
                 status = excluded.status, atype = excluded.atype, \
                 reset_password_key = excluded.reset_password_key, \
                 external_id = excluded.external_id, \
                 invited_by_email = excluded.invited_by_email",
            )
            .bind(&[
                JsValue::from_str(&self.uuid),
                JsValue::from_str(&self.user_uuid),
                JsValue::from_str(&self.org_uuid),
                JsValue::from_f64(self.access_all as f64),
                JsValue::from_str(&self.akey),
                JsValue::from_f64(self.status as f64),
                JsValue::from_f64(self.atype as f64),
                opt_str(&self.reset_password_key),
                opt_str(&self.external_id),
                opt_str(&self.invited_by_email),
            ])?;
        let _result = stmt.run().await?;
        Ok(())
    }

    pub async fn delete(self, db: &D1Database) -> DbResult<()> {
        let stmt = db
            .prepare("DELETE FROM users_organizations WHERE uuid = ?1")
            .bind(&[JsValue::from_str(&self.uuid)])?;
        let _result = stmt.run().await?;
        Ok(())
    }
}

fn opt_str(value: &Option<String>) -> JsValue {
    match value {
        Some(s) => JsValue::from_str(s),
        None => JsValue::NULL,
    }
}
