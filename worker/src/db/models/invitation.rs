use serde::{Deserialize, Serialize};
use worker::{D1Database, wasm_bindgen::JsValue};

use crate::db::DbResult;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Invitation {
    pub email: String,
}

impl Invitation {
    pub async fn new(db: &D1Database, email: &str) -> DbResult<()> {
        let stmt = db
            .prepare(
                "INSERT INTO invitations (email) VALUES (?1) ON CONFLICT(email) DO NOTHING",
            )
            .bind(&[JsValue::from_str(email)])?;
        let _result = stmt.run().await?;
        Ok(())
    }

    pub async fn find(db: &D1Database, email: &str) -> DbResult<Option<Self>> {
        let stmt = db
            .prepare("SELECT * FROM invitations WHERE email = ?1")
            .bind(&[JsValue::from_str(email)])?;
        Ok(stmt.first::<Self>(None).await?)
    }

    /// Delete the invitation if it exists. Returns `true` if a row was deleted.
    pub async fn take(db: &D1Database, email: &str) -> DbResult<bool> {
        if Self::find(db, email).await?.is_none() {
            return Ok(false);
        }
        let stmt = db
            .prepare("DELETE FROM invitations WHERE email = ?1")
            .bind(&[JsValue::from_str(email)])?;
        let _result = stmt.run().await?;
        Ok(true)
    }
}
