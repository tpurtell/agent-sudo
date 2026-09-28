//! Host request signatures.
//!
//! Every host -> service request carries four headers. The signature covers the
//! method, path and query, host id, timestamp, nonce, and a SHA-256 of the body.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

pub const HEADER_HOST: &str = "x-agent-sudo-host";
pub const HEADER_TIME: &str = "x-agent-sudo-time";
pub const HEADER_NONCE: &str = "x-agent-sudo-nonce";
pub const HEADER_SIGNATURE: &str = "x-agent-sudo-signature";

/// Maximum accepted clock skew between host and service.
pub const MAX_SKEW_SECS: i64 = 120;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SigningError {
    #[error("invalid key encoding")]
    BadKey,
    #[error("invalid signature encoding")]
    BadSignature,
    #[error("signature does not verify")]
    Mismatch,
}

pub fn canonical(
    method: &str,
    path_and_query: &str,
    host_id: &str,
    time: i64,
    nonce: &str,
    body: &[u8],
) -> Vec<u8> {
    format!(
        "agent-sudo-v1\n{}\n{}\n{}\n{}\n{}\n{}",
        method.to_ascii_uppercase(),
        path_and_query,
        host_id,
        time,
        nonce,
        hex::encode(Sha256::digest(body)),
    )
    .into_bytes()
}

pub fn generate_key() -> SigningKey {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).expect("operating system RNG unavailable");
    SigningKey::from_bytes(&seed)
}

pub fn encode_signing_key(key: &SigningKey) -> String {
    B64.encode(key.to_bytes())
}

pub fn decode_signing_key(text: &str) -> Result<SigningKey, SigningError> {
    let bytes: [u8; 32] = B64
        .decode(text.trim())
        .map_err(|_| SigningError::BadKey)?
        .try_into()
        .map_err(|_| SigningError::BadKey)?;
    Ok(SigningKey::from_bytes(&bytes))
}

pub fn encode_public_key(key: &VerifyingKey) -> String {
    B64.encode(key.to_bytes())
}

pub fn decode_public_key(text: &str) -> Result<VerifyingKey, SigningError> {
    let bytes: [u8; 32] = B64
        .decode(text.trim())
        .map_err(|_| SigningError::BadKey)?
        .try_into()
        .map_err(|_| SigningError::BadKey)?;
    VerifyingKey::from_bytes(&bytes).map_err(|_| SigningError::BadKey)
}

pub fn new_nonce() -> String {
    let mut nonce = [0u8; 16];
    getrandom::fill(&mut nonce).expect("operating system RNG unavailable");
    hex::encode(nonce)
}

pub fn sign(key: &SigningKey, message: &[u8]) -> String {
    B64.encode(key.sign(message).to_bytes())
}

pub fn verify(key: &VerifyingKey, message: &[u8], signature: &str) -> Result<(), SigningError> {
    let bytes: [u8; 64] = B64
        .decode(signature.trim())
        .map_err(|_| SigningError::BadSignature)?
        .try_into()
        .map_err(|_| SigningError::BadSignature)?;
    key.verify(message, &Signature::from_bytes(&bytes))
        .map_err(|_| SigningError::Mismatch)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_and_verify() {
        let key = generate_key();
        let public = decode_public_key(&encode_public_key(&key.verifying_key())).unwrap();
        let msg = canonical("post", "/api/v1/requests", "h1", 1700000000, "n", b"{}");
        let sig = sign(&key, &msg);
        assert!(verify(&public, &msg, &sig).is_ok());
        let tampered = canonical("post", "/api/v1/requests", "h1", 1700000000, "n", b"{ }");
        assert_eq!(
            verify(&public, &tampered, &sig),
            Err(SigningError::Mismatch)
        );
    }

    #[test]
    fn key_roundtrip() {
        let key = generate_key();
        let again = decode_signing_key(&encode_signing_key(&key)).unwrap();
        assert_eq!(key.to_bytes(), again.to_bytes());
        assert!(decode_public_key("not base64!").is_err());
    }
}
