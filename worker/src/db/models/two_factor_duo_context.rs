use serde::{Deserialize, Serialize};
use worker::{D1Database, wasm_bindgen::JsValue};

use crate::db::DbResult;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TwoFactorDuoContext {
    pub state: String,
    pub user_email: String,
    pub nonce: String,
    pub exp: i32,
}

impl TwoFactorDuoContext {
    pub fn new(state: String, user_email: String, nonce: String, exp: i32) -> Self {
        Self { state, user_email, nonce, exp }
    }

    pub async fn find_by_state(db: &D1Database, state: &str) -> DbResult<Option<Self>> {
        let stmt = db
            .prepare("SELECT * FROM twofactor_duo_ctx WHERE state = ?1")
            .bind(&[JsValue::from_str(state)])?;
        Ok(stmt.first::<Self>(None).await?)
    }

    pub async fn save(&self, db: &D1Database) -> DbResult<()> {
        let stmt = db
            .prepare(
                "INSERT INTO twofactor_duo_ctx (state, user_email, nonce, exp) \
                 VALUES (?1, ?2, ?3, ?4) \
                 ON CONFLICT(state) DO UPDATE SET \
                 user_email = excluded.user_email, nonce = excluded.nonce, exp = excluded.exp",
            )
            .bind(&[
                JsValue::from_str(&self.state),
                JsValue::from_str(&self.user_email),
                JsValue::from_str(&self.nonce),
                JsValue::from_f64(self.exp as f64),
            ])?;
        let _result = stmt.run().await?;
        Ok(())
    }

    pub async fn delete(self, db: &D1Database) -> DbResult<()> {
        let stmt = db
            .prepare("DELETE FROM twofactor_duo_ctx WHERE state = ?1")
            .bind(&[JsValue::from_str(&self.state)])?;
        let _result = stmt.run().await?;
        Ok(())
    }

    /// Delete all rows where `exp < now`.
    pub async fn purge_expired(db: &D1Database, now: i64) -> DbResult<()> {
        let stmt = db
            .prepare("DELETE FROM twofactor_duo_ctx WHERE exp < ?1")
            .bind(&[JsValue::from_f64(now as f64)])?;
        let _result = stmt.run().await?;
        Ok(())
    }
}
