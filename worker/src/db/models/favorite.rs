use worker::{D1Database, wasm_bindgen::JsValue};

use crate::db::DbResult;

/// Junction table: `(user_uuid, cipher_uuid)` is the composite primary key.
pub struct Favorite;

impl Favorite {
    pub async fn is_favorite(db: &D1Database, user_uuid: &str, cipher_uuid: &str) -> DbResult<bool> {
        let stmt = db
            .prepare("SELECT 1 FROM favorites WHERE user_uuid = ?1 AND cipher_uuid = ?2 LIMIT 1")
            .bind(&[JsValue::from_str(user_uuid), JsValue::from_str(cipher_uuid)])?;
        Ok(stmt.first::<serde_json::Value>(None).await?.is_some())
    }

    pub async fn set(db: &D1Database, user_uuid: &str, cipher_uuid: &str, favorite: bool) -> DbResult<()> {
        if favorite {
            let stmt = db
                .prepare(
                    "INSERT INTO favorites (user_uuid, cipher_uuid) VALUES (?1, ?2) \
                     ON CONFLICT(user_uuid, cipher_uuid) DO NOTHING",
                )
                .bind(&[JsValue::from_str(user_uuid), JsValue::from_str(cipher_uuid)])?;
            let _result = stmt.run().await?;
        } else {
            let stmt = db
                .prepare("DELETE FROM favorites WHERE user_uuid = ?1 AND cipher_uuid = ?2")
                .bind(&[JsValue::from_str(user_uuid), JsValue::from_str(cipher_uuid)])?;
            let _result = stmt.run().await?;
        }
        Ok(())
    }

    pub async fn cipher_uuids_for_user(db: &D1Database, user_uuid: &str) -> DbResult<Vec<String>> {
        let stmt = db
            .prepare("SELECT cipher_uuid FROM favorites WHERE user_uuid = ?1")
            .bind(&[JsValue::from_str(user_uuid)])?;
        let result = stmt.all().await?;
        #[derive(serde::Deserialize)]
        struct Row {
            cipher_uuid: String,
        }
        Ok(result.results::<Row>()?.into_iter().map(|r| r.cipher_uuid).collect())
    }
}
