use serde::{Deserialize, Serialize};
use worker::{D1Database, wasm_bindgen::JsValue};

use crate::db::DbResult;

// ---------------------------------------------------------------------------
// FolderCipher — junction table `folders_ciphers`
// ---------------------------------------------------------------------------

pub struct FolderCipher;

impl FolderCipher {
    pub async fn set(db: &D1Database, cipher_uuid: &str, folder_uuid: &str) -> DbResult<()> {
        let stmt = db
            .prepare(
                "INSERT INTO folders_ciphers (cipher_uuid, folder_uuid) VALUES (?1, ?2) \
                 ON CONFLICT(cipher_uuid, folder_uuid) DO NOTHING",
            )
            .bind(&[JsValue::from_str(cipher_uuid), JsValue::from_str(folder_uuid)])?;
        let _result = stmt.run().await?;
        Ok(())
    }

    pub async fn unset(db: &D1Database, cipher_uuid: &str, folder_uuid: &str) -> DbResult<()> {
        let stmt = db
            .prepare(
                "DELETE FROM folders_ciphers WHERE cipher_uuid = ?1 AND folder_uuid = ?2",
            )
            .bind(&[JsValue::from_str(cipher_uuid), JsValue::from_str(folder_uuid)])?;
        let _result = stmt.run().await?;
        Ok(())
    }

    pub async fn list_by_folder(db: &D1Database, folder_uuid: &str) -> DbResult<Vec<String>> {
        let stmt = db
            .prepare("SELECT cipher_uuid FROM folders_ciphers WHERE folder_uuid = ?1")
            .bind(&[JsValue::from_str(folder_uuid)])?;
        #[derive(serde::Deserialize)]
        struct Row {
            cipher_uuid: String,
        }
        Ok(stmt.all().await?.results::<Row>()?.into_iter().map(|r| r.cipher_uuid).collect())
    }

    pub async fn list_by_cipher(db: &D1Database, cipher_uuid: &str) -> DbResult<Vec<String>> {
        let stmt = db
            .prepare("SELECT folder_uuid FROM folders_ciphers WHERE cipher_uuid = ?1")
            .bind(&[JsValue::from_str(cipher_uuid)])?;
        #[derive(serde::Deserialize)]
        struct Row {
            folder_uuid: String,
        }
        Ok(stmt.all().await?.results::<Row>()?.into_iter().map(|r| r.folder_uuid).collect())
    }
}

// ---------------------------------------------------------------------------
// CipherCollection — junction table `ciphers_collections`
// ---------------------------------------------------------------------------

pub struct CipherCollection;

impl CipherCollection {
    pub async fn set(
        db: &D1Database,
        cipher_uuid: &str,
        collection_uuid: &str,
    ) -> DbResult<()> {
        let stmt = db
            .prepare(
                "INSERT INTO ciphers_collections (cipher_uuid, collection_uuid) VALUES (?1, ?2) \
                 ON CONFLICT(cipher_uuid, collection_uuid) DO NOTHING",
            )
            .bind(&[JsValue::from_str(cipher_uuid), JsValue::from_str(collection_uuid)])?;
        let _result = stmt.run().await?;
        Ok(())
    }

    pub async fn unset(
        db: &D1Database,
        cipher_uuid: &str,
        collection_uuid: &str,
    ) -> DbResult<()> {
        let stmt = db
            .prepare(
                "DELETE FROM ciphers_collections WHERE cipher_uuid = ?1 AND collection_uuid = ?2",
            )
            .bind(&[JsValue::from_str(cipher_uuid), JsValue::from_str(collection_uuid)])?;
        let _result = stmt.run().await?;
        Ok(())
    }

    pub async fn list_by_cipher(
        db: &D1Database,
        cipher_uuid: &str,
    ) -> DbResult<Vec<String>> {
        let stmt = db
            .prepare("SELECT collection_uuid FROM ciphers_collections WHERE cipher_uuid = ?1")
            .bind(&[JsValue::from_str(cipher_uuid)])?;
        #[derive(serde::Deserialize)]
        struct Row {
            collection_uuid: String,
        }
        Ok(stmt.all().await?.results::<Row>()?.into_iter().map(|r| r.collection_uuid).collect())
    }

    pub async fn list_by_collection(
        db: &D1Database,
        collection_uuid: &str,
    ) -> DbResult<Vec<String>> {
        let stmt = db
            .prepare("SELECT cipher_uuid FROM ciphers_collections WHERE collection_uuid = ?1")
            .bind(&[JsValue::from_str(collection_uuid)])?;
        #[derive(serde::Deserialize)]
        struct Row {
            cipher_uuid: String,
        }
        Ok(stmt.all().await?.results::<Row>()?.into_iter().map(|r| r.cipher_uuid).collect())
    }
}

// ---------------------------------------------------------------------------
// UserCollection — table `users_collections` (has permission fields)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserCollection {
    pub user_uuid: String,
    pub collection_uuid: String,
    pub read_only: i32,
    pub hide_passwords: i32,
    pub manage: i32,
}

impl UserCollection {
    pub fn new(
        user_uuid: String,
        collection_uuid: String,
        read_only: bool,
        hide_passwords: bool,
        manage: bool,
    ) -> Self {
        Self {
            user_uuid,
            collection_uuid,
            read_only: if read_only { 1 } else { 0 },
            hide_passwords: if hide_passwords { 1 } else { 0 },
            manage: if manage { 1 } else { 0 },
        }
    }

    pub async fn find_by_user(db: &D1Database, user_uuid: &str) -> DbResult<Vec<Self>> {
        let stmt = db
            .prepare("SELECT * FROM users_collections WHERE user_uuid = ?1")
            .bind(&[JsValue::from_str(user_uuid)])?;
        Ok(stmt.all().await?.results::<Self>()?)
    }

    pub async fn find_by_collection(
        db: &D1Database,
        collection_uuid: &str,
    ) -> DbResult<Vec<Self>> {
        let stmt = db
            .prepare("SELECT * FROM users_collections WHERE collection_uuid = ?1")
            .bind(&[JsValue::from_str(collection_uuid)])?;
        Ok(stmt.all().await?.results::<Self>()?)
    }

    pub async fn find(
        db: &D1Database,
        user_uuid: &str,
        collection_uuid: &str,
    ) -> DbResult<Option<Self>> {
        let stmt = db
            .prepare(
                "SELECT * FROM users_collections WHERE user_uuid = ?1 AND collection_uuid = ?2",
            )
            .bind(&[JsValue::from_str(user_uuid), JsValue::from_str(collection_uuid)])?;
        Ok(stmt.first::<Self>(None).await?)
    }

    pub async fn upsert(&self, db: &D1Database) -> DbResult<()> {
        let stmt = db
            .prepare(
                "INSERT INTO users_collections \
                 (user_uuid, collection_uuid, read_only, hide_passwords, manage) \
                 VALUES (?1, ?2, ?3, ?4, ?5) \
                 ON CONFLICT(user_uuid, collection_uuid) DO UPDATE SET \
                 read_only = excluded.read_only, hide_passwords = excluded.hide_passwords, \
                 manage = excluded.manage",
            )
            .bind(&[
                JsValue::from_str(&self.user_uuid),
                JsValue::from_str(&self.collection_uuid),
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
                "DELETE FROM users_collections WHERE user_uuid = ?1 AND collection_uuid = ?2",
            )
            .bind(&[
                JsValue::from_str(&self.user_uuid),
                JsValue::from_str(&self.collection_uuid),
            ])?;
        let _result = stmt.run().await?;
        Ok(())
    }

    pub async fn delete_all_by_collection(
        db: &D1Database,
        collection_uuid: &str,
    ) -> DbResult<()> {
        let stmt = db
            .prepare("DELETE FROM users_collections WHERE collection_uuid = ?1")
            .bind(&[JsValue::from_str(collection_uuid)])?;
        let _result = stmt.run().await?;
        Ok(())
    }
}
