use serde::{Deserialize, Serialize};
use worker::{D1Database, wasm_bindgen::JsValue};

use crate::db::DbResult;

/// Junction table `archives` with composite PK `(user_uuid, cipher_uuid)`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Archive {
    pub user_uuid: String,
    pub cipher_uuid: String,
    pub archived_at: String,
}

impl Archive {
    pub async fn set(db: &D1Database, user_uuid: &str, cipher_uuid: &str) -> DbResult<()> {
        let stmt = db
            .prepare(
                "INSERT INTO archives (user_uuid, cipher_uuid) VALUES (?1, ?2) \
                 ON CONFLICT(user_uuid, cipher_uuid) DO NOTHING",
            )
            .bind(&[JsValue::from_str(user_uuid), JsValue::from_str(cipher_uuid)])?;
        let _result = stmt.run().await?;
        Ok(())
    }

    pub async fn unset(db: &D1Database, user_uuid: &str, cipher_uuid: &str) -> DbResult<()> {
        let stmt = db
            .prepare(
                "DELETE FROM archives WHERE user_uuid = ?1 AND cipher_uuid = ?2",
            )
            .bind(&[JsValue::from_str(user_uuid), JsValue::from_str(cipher_uuid)])?;
        let _result = stmt.run().await?;
        Ok(())
    }

    pub async fn is_archived(
        db: &D1Database,
        user_uuid: &str,
        cipher_uuid: &str,
    ) -> DbResult<bool> {
        let stmt = db
            .prepare(
                "SELECT 1 FROM archives WHERE user_uuid = ?1 AND cipher_uuid = ?2 LIMIT 1",
            )
            .bind(&[JsValue::from_str(user_uuid), JsValue::from_str(cipher_uuid)])?;
        Ok(stmt.first::<serde_json::Value>(None).await?.is_some())
    }

    pub async fn archived_cipher_uuids_for_user(
        db: &D1Database,
        user_uuid: &str,
    ) -> DbResult<Vec<String>> {
        let stmt = db
            .prepare("SELECT cipher_uuid FROM archives WHERE user_uuid = ?1")
            .bind(&[JsValue::from_str(user_uuid)])?;
        #[derive(serde::Deserialize)]
        struct Row {
            cipher_uuid: String,
        }
        Ok(stmt.all().await?.results::<Row>()?.into_iter().map(|r| r.cipher_uuid).collect())
    }
}
