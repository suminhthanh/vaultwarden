use chrono::{NaiveDateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use worker::{D1Database, wasm_bindgen::JsValue};

use crate::db::DbResult;

pub const CLIENT_KDF_TYPE_DEFAULT: i32 = 0;
pub const CLIENT_KDF_ITER_DEFAULT: i32 = 600_000;

/// Mirrors the `users` table. Boolean columns are stored as `INTEGER` in SQLite/D1
/// so we keep them as `i32` here and convert at the API boundary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub uuid: String,
    pub enabled: i32,
    pub created_at: String,
    pub updated_at: String,
    pub verified_at: Option<String>,
    pub last_verifying_at: Option<String>,
    pub login_verify_count: i32,

    pub email: String,
    pub email_new: Option<String>,
    pub email_new_token: Option<String>,
    pub name: String,

    pub password_hash: Vec<u8>,
    pub salt: Vec<u8>,
    pub password_iterations: i32,
    pub password_hint: Option<String>,

    pub akey: String,
    pub private_key: Option<String>,
    pub public_key: Option<String>,

    pub totp_secret: Option<String>,
    pub totp_recover: Option<String>,

    pub security_stamp: String,
    pub stamp_exception: Option<String>,

    pub equivalent_domains: String,
    pub excluded_globals: String,

    pub client_kdf_type: i32,
    pub client_kdf_iter: i32,
    pub client_kdf_memory: Option<i32>,
    pub client_kdf_parallelism: Option<i32>,

    pub api_key: Option<String>,
    pub avatar_color: Option<String>,
    pub external_id: Option<String>,
}

/// Wire row type for `users` SELECTs that expose BLOB columns as `hex(col)`.
/// `serde_wasm_bindgen` can't decode JS Uint8Array → Vec<u8>, so we read
/// the BLOB as a hex string and decode in Rust.
#[derive(Deserialize)]
struct UserRow {
    uuid: String,
    enabled: i32,
    created_at: String,
    updated_at: String,
    verified_at: Option<String>,
    last_verifying_at: Option<String>,
    login_verify_count: i32,
    email: String,
    email_new: Option<String>,
    email_new_token: Option<String>,
    name: String,
    password_hash_hex: String,
    salt_hex: String,
    password_iterations: i32,
    password_hint: Option<String>,
    akey: String,
    private_key: Option<String>,
    public_key: Option<String>,
    totp_secret: Option<String>,
    totp_recover: Option<String>,
    security_stamp: String,
    stamp_exception: Option<String>,
    equivalent_domains: String,
    excluded_globals: String,
    client_kdf_type: i32,
    client_kdf_iter: i32,
    client_kdf_memory: Option<i32>,
    client_kdf_parallelism: Option<i32>,
    api_key: Option<String>,
    avatar_color: Option<String>,
    external_id: Option<String>,
}

impl User {
    pub fn new(email: &str, name: Option<String>) -> Self {
        let now = format_date(&Utc::now().naive_utc());
        let lower = email.to_lowercase();
        Self {
            uuid: Uuid::new_v4().to_string(),
            enabled: 1,
            created_at: now.clone(),
            updated_at: now,
            verified_at: None,
            last_verifying_at: None,
            login_verify_count: 0,
            email: lower.clone(),
            email_new: None,
            email_new_token: None,
            name: name.unwrap_or(lower),
            password_hash: Vec::new(),
            salt: random_bytes(64),
            password_iterations: CLIENT_KDF_ITER_DEFAULT,
            password_hint: None,
            akey: String::new(),
            private_key: None,
            public_key: None,
            totp_secret: None,
            totp_recover: None,
            security_stamp: Uuid::new_v4().to_string(),
            stamp_exception: None,
            equivalent_domains: "[]".into(),
            excluded_globals: "[]".into(),
            client_kdf_type: CLIENT_KDF_TYPE_DEFAULT,
            client_kdf_iter: CLIENT_KDF_ITER_DEFAULT,
            client_kdf_memory: None,
            client_kdf_parallelism: None,
            api_key: None,
            avatar_color: None,
            external_id: None,
        }
    }

    pub async fn find_by_uuid(db: &D1Database, uuid: &str) -> DbResult<Option<Self>> {
        let stmt = db
            .prepare(
                "SELECT uuid, enabled, created_at, updated_at, verified_at, last_verifying_at, login_verify_count, \
                 email, email_new, email_new_token, name, \
                 hex(password_hash) AS password_hash_hex, hex(salt) AS salt_hex, \
                 password_iterations, password_hint, akey, private_key, public_key, \
                 totp_secret, totp_recover, security_stamp, stamp_exception, \
                 equivalent_domains, excluded_globals, client_kdf_type, client_kdf_iter, \
                 client_kdf_memory, client_kdf_parallelism, api_key, avatar_color, external_id \
                 FROM users WHERE uuid = ?1",
            )
            .bind(&[JsValue::from_str(uuid)])?;
        let row: Option<UserRow> = stmt.first(None).await?;
        Ok(row.map(Self::from_row))
    }

    pub async fn find_by_email(db: &D1Database, email: &str) -> DbResult<Option<Self>> {
        let lower = email.to_lowercase();
        let stmt = db
            .prepare(
                "SELECT uuid, enabled, created_at, updated_at, verified_at, last_verifying_at, login_verify_count, \
                 email, email_new, email_new_token, name, \
                 hex(password_hash) AS password_hash_hex, hex(salt) AS salt_hex, \
                 password_iterations, password_hint, akey, private_key, public_key, \
                 totp_secret, totp_recover, security_stamp, stamp_exception, \
                 equivalent_domains, excluded_globals, client_kdf_type, client_kdf_iter, \
                 client_kdf_memory, client_kdf_parallelism, api_key, avatar_color, external_id \
                 FROM users WHERE email = ?1",
            )
            .bind(&[JsValue::from_str(&lower)])?;
        let row: Option<UserRow> = stmt.first(None).await?;
        Ok(row.map(Self::from_row))
    }

    fn from_row(row: UserRow) -> Self {
        Self {
            uuid: row.uuid,
            enabled: row.enabled,
            created_at: row.created_at,
            updated_at: row.updated_at,
            verified_at: row.verified_at,
            last_verifying_at: row.last_verifying_at,
            login_verify_count: row.login_verify_count,
            email: row.email,
            email_new: row.email_new,
            email_new_token: row.email_new_token,
            name: row.name,
            password_hash: hex_to_bytes(&row.password_hash_hex),
            salt: hex_to_bytes(&row.salt_hex),
            password_iterations: row.password_iterations,
            password_hint: row.password_hint,
            akey: row.akey,
            private_key: row.private_key,
            public_key: row.public_key,
            totp_secret: row.totp_secret,
            totp_recover: row.totp_recover,
            security_stamp: row.security_stamp,
            stamp_exception: row.stamp_exception,
            equivalent_domains: row.equivalent_domains,
            excluded_globals: row.excluded_globals,
            client_kdf_type: row.client_kdf_type,
            client_kdf_iter: row.client_kdf_iter,
            client_kdf_memory: row.client_kdf_memory,
            client_kdf_parallelism: row.client_kdf_parallelism,
            api_key: row.api_key,
            avatar_color: row.avatar_color,
            external_id: row.external_id,
        }
    }

    pub async fn save(&mut self, db: &D1Database) -> DbResult<()> {
        self.updated_at = format_date(&Utc::now().naive_utc());

        let stmt = db
            .prepare(
                "INSERT INTO users (\
                    uuid, enabled, created_at, updated_at, verified_at, last_verifying_at, login_verify_count, \
                    email, email_new, email_new_token, name, \
                    password_hash, salt, password_iterations, password_hint, \
                    akey, private_key, public_key, totp_secret, totp_recover, \
                    security_stamp, stamp_exception, equivalent_domains, excluded_globals, \
                    client_kdf_type, client_kdf_iter, client_kdf_memory, client_kdf_parallelism, \
                    api_key, avatar_color, external_id\
                 ) VALUES (\
                    ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, \
                    ?21, ?22, ?23, ?24, ?25, ?26, ?27, ?28, ?29, ?30, ?31\
                 ) ON CONFLICT(uuid) DO UPDATE SET \
                    enabled = excluded.enabled, updated_at = excluded.updated_at, \
                    verified_at = excluded.verified_at, last_verifying_at = excluded.last_verifying_at, \
                    login_verify_count = excluded.login_verify_count, email = excluded.email, \
                    email_new = excluded.email_new, email_new_token = excluded.email_new_token, name = excluded.name, \
                    password_hash = excluded.password_hash, salt = excluded.salt, \
                    password_iterations = excluded.password_iterations, password_hint = excluded.password_hint, \
                    akey = excluded.akey, private_key = excluded.private_key, public_key = excluded.public_key, \
                    totp_secret = excluded.totp_secret, totp_recover = excluded.totp_recover, \
                    security_stamp = excluded.security_stamp, stamp_exception = excluded.stamp_exception, \
                    equivalent_domains = excluded.equivalent_domains, excluded_globals = excluded.excluded_globals, \
                    client_kdf_type = excluded.client_kdf_type, client_kdf_iter = excluded.client_kdf_iter, \
                    client_kdf_memory = excluded.client_kdf_memory, client_kdf_parallelism = excluded.client_kdf_parallelism, \
                    api_key = excluded.api_key, avatar_color = excluded.avatar_color, external_id = excluded.external_id",
            )
            .bind(&[
                JsValue::from_str(&self.uuid),
                JsValue::from_f64(self.enabled as f64),
                JsValue::from_str(&self.created_at),
                JsValue::from_str(&self.updated_at),
                opt_str(&self.verified_at),
                opt_str(&self.last_verifying_at),
                JsValue::from_f64(self.login_verify_count as f64),
                JsValue::from_str(&self.email),
                opt_str(&self.email_new),
                opt_str(&self.email_new_token),
                JsValue::from_str(&self.name),
                bytes_as_blob(&self.password_hash),
                bytes_as_blob(&self.salt),
                JsValue::from_f64(self.password_iterations as f64),
                opt_str(&self.password_hint),
                JsValue::from_str(&self.akey),
                opt_str(&self.private_key),
                opt_str(&self.public_key),
                opt_str(&self.totp_secret),
                opt_str(&self.totp_recover),
                JsValue::from_str(&self.security_stamp),
                opt_str(&self.stamp_exception),
                JsValue::from_str(&self.equivalent_domains),
                JsValue::from_str(&self.excluded_globals),
                JsValue::from_f64(self.client_kdf_type as f64),
                JsValue::from_f64(self.client_kdf_iter as f64),
                opt_i32(self.client_kdf_memory),
                opt_i32(self.client_kdf_parallelism),
                opt_str(&self.api_key),
                opt_str(&self.avatar_color),
                opt_str(&self.external_id),
            ])?;
        let _result = stmt.run().await?;
        Ok(())
    }

    pub async fn delete(self, db: &D1Database) -> DbResult<()> {
        let stmt = db.prepare("DELETE FROM users WHERE uuid = ?1").bind(&[JsValue::from_str(&self.uuid)])?;
        let _result = stmt.run().await?;
        Ok(())
    }

    /// Hash and store the master password using the user's existing salt and
    /// `password_iterations`. Matches upstream `User::set_password`'s base case
    /// (without the optional reset_security_stamp / additional_argon2 paths).
    pub fn set_password(&mut self, password: &str) {
        self.password_hash = crate::crypto::hash_password(
            password.as_bytes(),
            &self.salt,
            self.password_iterations as u32,
        );
    }

    pub fn check_valid_password(&self, password: &str) -> bool {
        if self.password_hash.is_empty() {
            return false;
        }
        crate::crypto::verify_password_hash(
            password.as_bytes(),
            &self.salt,
            &self.password_hash,
            self.password_iterations as u32,
        )
    }
}

fn format_date(dt: &NaiveDateTime) -> String {
    dt.and_utc().to_rfc3339_opts(chrono::SecondsFormat::Micros, true)
}

fn random_bytes(len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    let _ = getrandom::getrandom(&mut buf);
    buf
}

fn opt_str(value: &Option<String>) -> JsValue {
    match value {
        Some(s) => JsValue::from_str(s),
        None => JsValue::NULL,
    }
}

fn opt_i32(value: Option<i32>) -> JsValue {
    match value {
        Some(v) => JsValue::from_f64(v as f64),
        None => JsValue::NULL,
    }
}

fn bytes_as_blob(bytes: &[u8]) -> JsValue {
    let arr = js_sys::Uint8Array::new_with_length(bytes.len() as u32);
    arr.copy_from(bytes);
    arr.into()
}

fn hex_to_bytes(hex: &str) -> Vec<u8> {
    if hex.is_empty() {
        return Vec::new();
    }
    let mut out = Vec::with_capacity(hex.len() / 2);
    let bytes = hex.as_bytes();
    let mut i = 0;
    while i + 1 < bytes.len() {
        let hi = hex_nibble(bytes[i]);
        let lo = hex_nibble(bytes[i + 1]);
        out.push((hi << 4) | lo);
        i += 2;
    }
    out
}

fn hex_nibble(b: u8) -> u8 {
    match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'f' => b - b'a' + 10,
        b'A'..=b'F' => b - b'A' + 10,
        _ => 0,
    }
}
