use serde::{Deserialize, Serialize};
use uuid::Uuid;
use worker::{D1Database, wasm_bindgen::JsValue};

use crate::db::DbResult;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Attachment {
    pub id: String,
    pub cipher_uuid: String,
    pub file_name: String,
    pub file_size: i32,
    pub akey: Option<String>,
}

impl Attachment {
    pub fn new(id: String, cipher_uuid: String, file_name: String, file_size: i32, akey: Option<String>) -> Self {
        Self {
            id,
            cipher_uuid,
            file_name,
            file_size,
            akey,
        }
    }

    pub fn new_random(cipher_uuid: String, file_name: String, file_size: i32) -> Self {
        Self::new(Uuid::new_v4().to_string(), cipher_uuid, file_name, file_size, None)
    }

    pub async fn find_by_id(db: &D1Database, id: &str) -> DbResult<Option<Self>> {
        let stmt =
            db.prepare("SELECT * FROM attachments WHERE id = ?1").bind(&[JsValue::from_str(id)])?;
        Ok(stmt.first::<Self>(None).await?)
    }

    pub async fn find_by_cipher(db: &D1Database, cipher_uuid: &str) -> DbResult<Vec<Self>> {
        let stmt = db
            .prepare("SELECT * FROM attachments WHERE cipher_uuid = ?1")
            .bind(&[JsValue::from_str(cipher_uuid)])?;
        Ok(stmt.all().await?.results::<Self>()?)
    }

    pub async fn save(&self, db: &D1Database) -> DbResult<()> {
        let stmt = db
            .prepare(
                "INSERT INTO attachments (id, cipher_uuid, file_name, file_size, akey) \
                 VALUES (?1, ?2, ?3, ?4, ?5) \
                 ON CONFLICT(id) DO UPDATE SET \
                 cipher_uuid = excluded.cipher_uuid, file_name = excluded.file_name, \
                 file_size = excluded.file_size, akey = excluded.akey",
            )
            .bind(&[
                JsValue::from_str(&self.id),
                JsValue::from_str(&self.cipher_uuid),
                JsValue::from_str(&self.file_name),
                JsValue::from_f64(self.file_size as f64),
                opt_str(&self.akey),
            ])?;
        let _result = stmt.run().await?;
        Ok(())
    }

    pub async fn delete(self, db: &D1Database) -> DbResult<()> {
        let stmt =
            db.prepare("DELETE FROM attachments WHERE id = ?1").bind(&[JsValue::from_str(&self.id)])?;
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
