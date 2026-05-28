//! Password hashing matching upstream Vaultwarden's `crypto::hash_password`:
//! PBKDF2-HMAC-SHA256, 32-byte output, server-side iteration count from
//! `User::password_iterations`.

use hmac::Hmac;
use sha2::Sha256;
use subtle::ConstantTimeEq;

const OUTPUT_LEN: usize = 32;

pub fn hash_password(secret: &[u8], salt: &[u8], iterations: u32) -> Vec<u8> {
    assert!(iterations > 0, "iterations can't be zero");
    let mut out = vec![0u8; OUTPUT_LEN];
    pbkdf2::pbkdf2::<Hmac<Sha256>>(secret, salt, iterations, &mut out).expect("hmac sha256 keying");
    out
}

pub fn verify_password_hash(secret: &[u8], salt: &[u8], previous: &[u8], iterations: u32) -> bool {
    let candidate = hash_password(secret, salt, iterations);
    candidate.ct_eq(previous).into()
}
