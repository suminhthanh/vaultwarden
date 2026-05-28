use serde::{Deserialize, Serialize};
use worker::{D1Database, wasm_bindgen::JsValue};

use crate::db::DbResult;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SsoUser {
    pub user_uuid: String,
    pub identifier: String,
    pub created_at: String,
}

impl SsoUser {
    pub fn new(user_uuid: String, identifier: String) -> Self {
        Self {
            user_uuid,
            identifier,
            // created_at is set by the DB DEFAULT; supply a placeholder for INSERT
            created_at: String::new(),
        }
    }

    pub async fn find_by_user_uuid(db: &D1Database, user_uuid: &str) -> DbResult<Option<Self>> {
        let stmt = db
            .prepare("SELECT * FROM sso_users WHERE user_uuid = ?1")
            .bind(&[JsValue::from_str(user_uuid)])?;
        Ok(stmt.first::<Self>(None).await?)
    }

    pub async fn find_by_identifier(db: &D1Database, identifier: &str) -> DbResult<Option<Self>> {
        let stmt = db
            .prepare("SELECT * FROM sso_users WHERE identifier = ?1")
            .bind(&[JsValue::from_str(identifier)])?;
        Ok(stmt.first::<Self>(None).await?)
    }

    pub async fn save(&self, db: &D1Database) -> DbResult<()> {
        let stmt = db
            .prepare(
                "INSERT INTO sso_users (user_uuid, identifier) VALUES (?1, ?2) \
                 ON CONFLICT(user_uuid) DO UPDATE SET identifier = excluded.identifier",
            )
            .bind(&[JsValue::from_str(&self.user_uuid), JsValue::from_str(&self.identifier)])?;
        let _result = stmt.run().await?;
        Ok(())
    }

    pub async fn delete(self, db: &D1Database) -> DbResult<()> {
        let stmt = db
            .prepare("DELETE FROM sso_users WHERE user_uuid = ?1")
            .bind(&[JsValue::from_str(&self.user_uuid)])?;
        let _result = stmt.run().await?;
        Ok(())
    }
}
