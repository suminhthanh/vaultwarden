// Audit crate: confirm Vaultwarden's crypto deps compile to wasm32-unknown-unknown.
// Touch each public API so the linker pulls them in.
#![allow(unused_qualifications, let_underscore_drop, unused_results)]

pub fn touch_jsonwebtoken() {
    let _alg = jsonwebtoken::Algorithm::RS256;
}

pub fn touch_argon2() {
    use argon2::{Argon2, PasswordHasher, password_hash::SaltString};
    let argon = Argon2::default();
    let salt = SaltString::encode_b64(b"abcdefghij12").unwrap();
    let _hashed = argon.hash_password(b"x", &salt);
}

pub fn touch_totp_lite() {
    let _otp = totp_lite::totp::<totp_lite::Sha1>(b"x", 0);
}

// webauthn-rs 0.5.5 transitively pulls openssl-sys (via webauthn-attestation-ca),
// which fails to build on wasm32. Tracked as a phase-0 finding; substitute or
// hand-roll WebAuthn assertion verification.

pub fn touch_rsa_sha_aes() {
    let _rsa_size = std::mem::size_of::<rsa::RsaPublicKey>();
    let _sha_size = std::mem::size_of::<sha2::Sha256>();
    let _aes_size = std::mem::size_of::<aes_gcm::Aes256Gcm>();
}

pub fn touch_passkey() {
    let _ty_size = std::mem::size_of::<passkey_types::webauthn::PublicKeyCredentialDescriptor>();
}
