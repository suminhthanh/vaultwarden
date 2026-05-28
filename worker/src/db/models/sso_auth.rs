use serde::{Deserialize, Serialize};
use worker::{D1Database, wasm_bindgen::JsValue};

use crate::db::DbResult;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SsoAuth {
    pub state: String,
    pub client_challenge: String,
    pub nonce: String,
    pub redirect_uri: String,
    pub code_response: Option<String>,
    pub auth_response: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    pub binding_hash: Option<String>,
    pub code_response_error: Option<String>,
}

impl SsoAuth {
    pub fn new(
        state: String,
        client_challenge: String,
        nonce: String,
        redirect_uri: String,
    ) -> Self {
        Self {
            state,
            client_challenge,
            nonce,
            redirect_uri,
            code_response: None,
            auth_response: None,
            // created_at / updated_at default to CURRENT_TIMESTAMP in DB
            created_at: String::new(),
            updated_at: String::new(),
            binding_hash: None,
            code_response_error: None,
        }
    }

    pub async fn find_by_state(db: &D1Database, state: &str) -> DbResult<Option<Self>> {
        let stmt = db
            .prepare("SELECT * FROM sso_auth WHERE state = ?1")
            .bind(&[JsValue::from_str(state)])?;
        Ok(stmt.first::<Self>(None).await?)
    }

    pub async fn save(&self, db: &D1Database) -> DbResult<()> {
        let stmt = db
            .prepare(
                "INSERT INTO sso_auth (state, client_challenge, nonce, redirect_uri, \
                 code_response, auth_response, binding_hash, code_response_error) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8) \
                 ON CONFLICT(state) DO UPDATE SET \
                 client_challenge = excluded.client_challenge, nonce = excluded.nonce, \
                 redirect_uri = excluded.redirect_uri, \
                 code_response = excluded.code_response, \
                 auth_response = excluded.auth_response, \
                 updated_at = CURRENT_TIMESTAMP, \
                 binding_hash = excluded.binding_hash, \
                 code_response_error = excluded.code_response_error",
            )
            .bind(&[
                JsValue::from_str(&self.state),
                JsValue::from_str(&self.client_challenge),
                JsValue::from_str(&self.nonce),
                JsValue::from_str(&self.redirect_uri),
                opt_str(&self.code_response),
                opt_str(&self.auth_response),
                opt_str(&self.binding_hash),
                opt_str(&self.code_response_error),
            ])?;
        let _result = stmt.run().await?;
        Ok(())
    }

    pub async fn delete(self, db: &D1Database) -> DbResult<()> {
        let stmt = db
            .prepare("DELETE FROM sso_auth WHERE state = ?1")
            .bind(&[JsValue::from_str(&self.state)])?;
        let _result = stmt.run().await?;
        Ok(())
    }

    /// Delete rows older than `before` (RFC3339 string) based on `created_at`.
    pub async fn purge_old(db: &D1Database, before: &str) -> DbResult<()> {
        let stmt = db
            .prepare("DELETE FROM sso_auth WHERE created_at < ?1")
            .bind(&[JsValue::from_str(before)])?;
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
