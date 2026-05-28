#![allow(dead_code)]

use axum::{
    extract::FromRequestParts,
    http::{StatusCode, request::Parts},
};
use chrono::{Duration, Utc};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::future::Future;

use crate::AppState;
use crate::db::models::{Device, User};

const JWT_ALGORITHM: Algorithm = Algorithm::RS256;

pub const DEFAULT_ACCESS_VALIDITY_SECS: i64 = 3600;
pub const DEFAULT_REFRESH_VALIDITY_DAYS: i64 = 30;

#[derive(Debug)]
pub enum AuthError {
    MissingKey(&'static str),
    InvalidKey(String),
    InvalidToken(String),
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingKey(name) => write!(f, "missing secret: {name}"),
            Self::InvalidKey(msg) => write!(f, "invalid key: {msg}"),
            Self::InvalidToken(msg) => write!(f, "invalid token: {msg}"),
        }
    }
}

impl std::error::Error for AuthError {}

pub struct JwtKeys {
    pub private_pem: String,
    pub public_pem: String,
    pub login_issuer: String,
}

/// `.dev.vars` requires single-line values, so PEMs land with literal `\n`
/// sequences. Replace those with real newlines before handing to jsonwebtoken.
/// In production, secrets stored via `wrangler secret put < file.pem` keep
/// real newlines and pass through unchanged.
fn read_pem_secret(env: &worker::Env, name: &'static str) -> Result<String, AuthError> {
    let raw = env.secret(name).map_err(|_| AuthError::MissingKey(name))?.to_string();
    Ok(raw.replace("\\n", "\n"))
}

impl JwtKeys {
    pub fn from_env(env: &worker::Env) -> Result<Self, AuthError> {
        let private_pem = read_pem_secret(env, "JWT_RSA_PRIVATE_KEY")?;
        let public_pem = read_pem_secret(env, "JWT_RSA_PUBLIC_KEY")?;
        let domain = env
            .var("DOMAIN")
            .map(|v| v.to_string())
            .unwrap_or_else(|_| "http://localhost".to_owned());
        Ok(Self { private_pem, public_pem, login_issuer: format!("{domain}|login") })
    }

    fn encoding_key(&self) -> Result<EncodingKey, AuthError> {
        EncodingKey::from_rsa_pem(self.private_pem.as_bytes()).map_err(|e| AuthError::InvalidKey(e.to_string()))
    }

    fn decoding_key(&self) -> Result<DecodingKey, AuthError> {
        DecodingKey::from_rsa_pem(self.public_pem.as_bytes()).map_err(|e| AuthError::InvalidKey(e.to_string()))
    }

    pub fn encode<T: Serialize>(&self, claims: &T) -> Result<String, AuthError> {
        let header = Header::new(JWT_ALGORITHM);
        encode(&header, claims, &self.encoding_key()?).map_err(|e| AuthError::InvalidToken(e.to_string()))
    }

    pub fn decode<T: DeserializeOwned>(&self, token: &str, issuer: &str) -> Result<T, AuthError> {
        let mut validation = Validation::new(JWT_ALGORITHM);
        validation.set_issuer(&[issuer]);
        decode::<T>(token, &self.decoding_key()?, &validation)
            .map(|d| d.claims)
            .map_err(|e| AuthError::InvalidToken(e.to_string()))
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LoginJwtClaims {
    pub nbf: i64,
    pub exp: i64,
    pub iss: String,
    pub sub: String,

    pub premium: bool,
    pub name: String,
    pub email: String,
    pub email_verified: bool,

    pub sstamp: String,
    pub device: String,
    pub devicetype: String,
    pub client_id: String,

    pub scope: Vec<String>,
    pub amr: Vec<String>,
}

impl LoginJwtClaims {
    pub fn new_for(
        keys: &JwtKeys,
        device: &Device,
        user: &User,
        scope: Vec<String>,
        client_id: Option<String>,
    ) -> Self {
        let now = Utc::now();
        let nbf = now.timestamp();
        let exp = (now + Duration::seconds(DEFAULT_ACCESS_VALIDITY_SECS)).timestamp();
        Self {
            nbf,
            exp,
            iss: keys.login_issuer.clone(),
            sub: user.uuid.clone(),
            premium: true,
            name: user.name.clone(),
            email: user.email.clone(),
            email_verified: user.verified_at.is_some(),
            sstamp: user.security_stamp.clone(),
            device: device.uuid.clone(),
            devicetype: device.atype.to_string(),
            client_id: client_id.unwrap_or_else(|| "undefined".to_owned()),
            scope,
            amr: vec!["Application".into()],
        }
    }

    pub fn expires_in(&self) -> i64 {
        self.exp - Utc::now().timestamp()
    }
}

/// Short-lived JWT minted by `/accounts/register/send-verification-email` and
/// presented back on `/accounts/register/finish` to prove the email address
/// was verified (or to short-circuit the verification step when SMTP is not
/// configured). Mirrors upstream's `RegisterVerifyClaims`.
#[derive(Debug, Serialize, Deserialize)]
pub struct RegisterVerifyClaims {
    pub nbf: i64,
    pub exp: i64,
    pub iss: String,
    pub sub: String, // email
    pub name: Option<String>,
    pub verified: bool,
}

impl RegisterVerifyClaims {
    pub const ISSUER_SUFFIX: &'static str = "|register_verify";

    pub fn issuer(keys: &JwtKeys) -> String {
        let domain = keys.login_issuer.trim_end_matches("|login");
        format!("{domain}{}", Self::ISSUER_SUFFIX)
    }

    pub fn new(keys: &JwtKeys, email: String, name: Option<String>, verified: bool) -> Self {
        let now = Utc::now();
        Self {
            nbf: now.timestamp(),
            exp: (now + Duration::hours(1)).timestamp(),
            iss: Self::issuer(keys),
            sub: email,
            name,
            verified,
        }
    }
}

/// JWT used by the anonymous file-send download URL. Path-scoped to a single
/// send + file id; expires when the send expires.
#[derive(Debug, Serialize, Deserialize)]
pub struct SendFileClaims {
    pub nbf: i64,
    pub exp: i64,
    pub iss: String,
    pub sub: String,           // send uuid
    pub fid: String,           // file id
}

impl SendFileClaims {
    pub const ISSUER_SUFFIX: &'static str = "|send_file";

    pub fn issuer(keys: &JwtKeys) -> String {
        let domain = keys.login_issuer.trim_end_matches("|login");
        format!("{domain}{}", Self::ISSUER_SUFFIX)
    }

    pub fn new(keys: &JwtKeys, send_uuid: String, file_id: String, expires: chrono::DateTime<Utc>) -> Self {
        let now = Utc::now();
        Self {
            nbf: now.timestamp(),
            exp: expires.timestamp(),
            iss: Self::issuer(keys),
            sub: send_uuid,
            fid: file_id,
        }
    }
}

/// JWT used to bind a verify-email link to a specific user. Issued at
/// /api/accounts/verify-email and consumed at /api/accounts/verify-email-token.
#[derive(Debug, Serialize, Deserialize)]
pub struct VerifyEmailClaims {
    pub nbf: i64,
    pub exp: i64,
    pub iss: String,
    pub sub: String, // user uuid
}

impl VerifyEmailClaims {
    pub const ISSUER_SUFFIX: &'static str = "|verify_email";

    pub fn issuer(keys: &JwtKeys) -> String {
        let domain = keys.login_issuer.trim_end_matches("|login");
        format!("{domain}{}", Self::ISSUER_SUFFIX)
    }

    pub fn new(keys: &JwtKeys, user_uuid: String) -> Self {
        let now = Utc::now();
        Self {
            nbf: now.timestamp(),
            exp: (now + Duration::hours(24)).timestamp(),
            iss: Self::issuer(keys),
            sub: user_uuid,
        }
    }
}

/// JWT used to bind a delete-recover link. Same shape as VerifyEmailClaims
/// but a different issuer suffix so a verify token can't be replayed for
/// account deletion.
#[derive(Debug, Serialize, Deserialize)]
pub struct DeleteRecoverClaims {
    pub nbf: i64,
    pub exp: i64,
    pub iss: String,
    pub sub: String, // user uuid
}

impl DeleteRecoverClaims {
    pub const ISSUER_SUFFIX: &'static str = "|delete_recover";

    pub fn issuer(keys: &JwtKeys) -> String {
        let domain = keys.login_issuer.trim_end_matches("|login");
        format!("{domain}{}", Self::ISSUER_SUFFIX)
    }

    pub fn new(keys: &JwtKeys, user_uuid: String) -> Self {
        let now = Utc::now();
        Self {
            nbf: now.timestamp(),
            exp: (now + Duration::hours(1)).timestamp(),
            iss: Self::issuer(keys),
            sub: user_uuid,
        }
    }
}

/// Authenticated request context. Mirrors upstream's `Headers` request guard:
/// every authenticated handler receives the resolved User and Device, plus the
/// raw claims for ad-hoc inspection.
pub struct Headers {
    pub user: User,
    pub device: Device,
    pub claims: LoginJwtClaims,
}

impl<S> FromRequestParts<S> for Headers
where
    S: Send + Sync,
    AppState: axum::extract::FromRef<S>,
{
    type Rejection = (StatusCode, axum::Json<serde_json::Value>);

    fn from_request_parts(
        parts: &mut Parts,
        state: &S,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send {
        use axum::extract::FromRef;

        let app: AppState = AppState::from_ref(state);
        let auth_header = parts
            .headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);

        worker::send::SendFuture::new(async move {
            let auth_header = auth_header.ok_or_else(|| unauthorized("missing Authorization header"))?;
            let token = auth_header
                .strip_prefix("Bearer ")
                .or_else(|| auth_header.strip_prefix("bearer "))
                .ok_or_else(|| unauthorized("Authorization must be Bearer"))?;

            let claims: LoginJwtClaims = app
                .keys
                .decode(token, &app.keys.login_issuer)
                .map_err(|e| unauthorized(&format!("invalid token: {e}")))?;

            let user = User::find_by_uuid(&app.db, &claims.sub)
                .await
                .map_err(|_| internal_error("user lookup failed"))?
                .ok_or_else(|| unauthorized("user not found"))?;

            if user.security_stamp != claims.sstamp {
                return Err(unauthorized("security stamp invalidated"));
            }
            if user.enabled == 0 {
                return Err(unauthorized("user disabled"));
            }

            let device = Device::find(&app.db, &claims.device, &user.uuid)
                .await
                .map_err(|_| internal_error("device lookup failed"))?
                .ok_or_else(|| unauthorized("device not found"))?;

            Ok(Self { user, device, claims })
        })
    }
}

fn unauthorized(msg: &str) -> (StatusCode, axum::Json<serde_json::Value>) {
    (
        StatusCode::UNAUTHORIZED,
        axum::Json(serde_json::json!({
            "error": "invalid_token",
            "error_description": msg,
            "ErrorModel": { "Message": msg },
        })),
    )
}

fn internal_error(msg: &str) -> (StatusCode, axum::Json<serde_json::Value>) {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        axum::Json(serde_json::json!({ "error": "server_error", "error_description": msg })),
    )
}
