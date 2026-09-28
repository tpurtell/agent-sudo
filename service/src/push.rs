//! Web Push: VAPID (RFC 8292) and aes128gcm message encryption (RFC 8291).

use std::time::Duration;

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes128Gcm, Nonce};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use hkdf::Hkdf;
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::{PublicKey, SecretKey};
use rusqlite::params;
use serde::Serialize;
use serde_json::json;
use sha2::Sha256;

use crate::db::Db;
use crate::util::{now_ms, now_secs};

#[derive(Clone)]
pub struct Push {
    key: SigningKey,
    pub public_key_b64: String,
    subject: String,
    http: reqwest::Client,
    enabled: bool,
}

#[derive(Debug, Clone)]
pub struct Subscription {
    pub id: String,
    pub endpoint: String,
    pub p256dh: String,
    pub auth: String,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Delivery {
    Sent,
    /// The subscription no longer exists and should be removed.
    Gone,
    Failed(String),
}

impl Push {
    /// Load the VAPID key from settings, generating one on first start.
    pub fn load(db: &Db, subject: &str, enabled: bool) -> anyhow::Result<Push> {
        let key = match db.setting("vapid_private_key")? {
            Some(b64) => SigningKey::from_slice(&B64URL.decode(b64)?)?,
            None => {
                let secret = SecretKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
                db.set_setting("vapid_private_key", &B64URL.encode(secret.to_bytes()))?;
                SigningKey::from(secret)
            }
        };
        let public = key.verifying_key().to_encoded_point(false);
        Ok(Push {
            public_key_b64: B64URL.encode(public.as_bytes()),
            key,
            subject: subject.to_string(),
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(15))
                .build()?,
            enabled,
        })
    }

    pub fn enabled(&self) -> bool {
        self.enabled
    }

    fn vapid_header(&self, endpoint: &str) -> anyhow::Result<String> {
        let url = url::Url::parse(endpoint)?;
        let aud = format!("{}://{}", url.scheme(), url.host_str().unwrap_or_default());
        let header = B64URL.encode(br#"{"typ":"JWT","alg":"ES256"}"#);
        let claims = B64URL.encode(
            json!({"aud": aud, "exp": now_secs() + 12 * 3600, "sub": self.subject}).to_string(),
        );
        let signing_input = format!("{header}.{claims}");
        let sig: Signature = self.key.sign(signing_input.as_bytes());
        Ok(format!(
            "vapid t={signing_input}.{}, k={}",
            B64URL.encode(sig.to_bytes()),
            self.public_key_b64
        ))
    }

    pub async fn send<T: Serialize>(
        &self,
        sub: &Subscription,
        payload: &T,
        ttl: u32,
        topic: Option<&str>,
    ) -> Delivery {
        if !self.enabled {
            return Delivery::Failed("push disabled".into());
        }
        let body = match serde_json::to_vec(payload)
            .map_err(anyhow::Error::from)
            .and_then(|p| encrypt(&p, &sub.p256dh, &sub.auth))
        {
            Ok(b) => b,
            Err(e) => return Delivery::Failed(format!("encrypt: {e}")),
        };
        let auth = match self.vapid_header(&sub.endpoint) {
            Ok(a) => a,
            Err(e) => return Delivery::Failed(format!("vapid: {e}")),
        };
        let mut req = self
            .http
            .post(&sub.endpoint)
            .header("Authorization", auth)
            .header("Content-Encoding", "aes128gcm")
            .header("Content-Type", "application/octet-stream")
            .header("TTL", ttl.to_string())
            .header("Urgency", "high");
        if let Some(topic) = topic {
            req = req.header("Topic", topic);
        }
        match req.body(body).send().await {
            Ok(r) if r.status().is_success() => Delivery::Sent,
            Ok(r) if r.status() == 404 || r.status() == 410 => Delivery::Gone,
            Ok(r) => {
                let status = r.status();
                let text = r.text().await.unwrap_or_default();
                Delivery::Failed(format!(
                    "{status}: {}",
                    text.chars().take(200).collect::<String>()
                ))
            }
            Err(e) => Delivery::Failed(e.to_string()),
        }
    }
}

/// Encrypt a payload for a subscription (RFC 8291, single aes128gcm record).
pub fn encrypt(payload: &[u8], p256dh_b64: &str, auth_b64: &str) -> anyhow::Result<Vec<u8>> {
    let ua_public_bytes = B64URL.decode(p256dh_b64.trim_end_matches('='))?;
    let auth_secret = B64URL.decode(auth_b64.trim_end_matches('='))?;
    let ua_public = PublicKey::from_sec1_bytes(&ua_public_bytes)?;
    let as_secret =
        p256::ecdh::EphemeralSecret::random(&mut p256::elliptic_curve::rand_core::OsRng);
    let as_public = as_secret.public_key().to_encoded_point(false);
    let shared = as_secret.diffie_hellman(&ua_public);
    let salt = crate::util::random_bytes::<16>();
    encrypt_with(
        payload,
        &ua_public_bytes,
        &auth_secret,
        shared.raw_secret_bytes(),
        as_public.as_bytes(),
        &salt,
    )
}

pub fn encrypt_with(
    payload: &[u8],
    ua_public: &[u8],
    auth_secret: &[u8],
    ecdh_secret: &[u8],
    as_public: &[u8],
    salt: &[u8; 16],
) -> anyhow::Result<Vec<u8>> {
    let mut key_info = b"WebPush: info\0".to_vec();
    key_info.extend_from_slice(ua_public);
    key_info.extend_from_slice(as_public);
    let mut ikm = [0u8; 32];
    Hkdf::<Sha256>::new(Some(auth_secret), ecdh_secret)
        .expand(&key_info, &mut ikm)
        .map_err(|_| anyhow::anyhow!("hkdf"))?;
    let prk = Hkdf::<Sha256>::new(Some(salt), &ikm);
    let mut cek = [0u8; 16];
    let mut nonce = [0u8; 12];
    prk.expand(b"Content-Encoding: aes128gcm\0", &mut cek)
        .map_err(|_| anyhow::anyhow!("hkdf"))?;
    prk.expand(b"Content-Encoding: nonce\0", &mut nonce)
        .map_err(|_| anyhow::anyhow!("hkdf"))?;
    let mut plaintext = payload.to_vec();
    plaintext.push(0x02); // last-record delimiter, no padding
    let cipher = Aes128Gcm::new_from_slice(&cek)?;
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), plaintext.as_ref())
        .map_err(|_| anyhow::anyhow!("aes-gcm"))?;
    let mut out = Vec::with_capacity(16 + 4 + 1 + as_public.len() + ciphertext.len());
    out.extend_from_slice(salt);
    out.extend_from_slice(&4096u32.to_be_bytes());
    out.push(as_public.len() as u8);
    out.extend_from_slice(as_public);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Whether notifications from this push service can show action buttons. Chrome
/// and Edge can; Safari (Apple's service) and Firefox (Mozilla's) cannot.
pub fn shows_actions(endpoint: &str) -> bool {
    let host = endpoint
        .strip_prefix("https://")
        .and_then(|r| r.split('/').next())
        .unwrap_or("");
    host == "fcm.googleapis.com" || host.ends_with(".notify.windows.com")
}

pub fn subscriptions_for_approvers(db: &Db) -> anyhow::Result<Vec<Subscription>> {
    let conn = db.lock();
    let mut stmt = conn.prepare(
        "SELECT p.id, p.endpoint, p.p256dh, p.auth FROM push_subscriptions p
         JOIN devices d ON d.id = p.device_id JOIN users u ON u.id = d.user_id
         WHERE d.revoked_at IS NULL AND u.disabled_at IS NULL AND u.role IN ('admin', 'approver')",
    )?;
    let subs = stmt
        .query_map([], |r| {
            Ok(Subscription {
                id: r.get(0)?,
                endpoint: r.get(1)?,
                p256dh: r.get(2)?,
                auth: r.get(3)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(subs)
}

pub fn subscriptions_for_device(db: &Db, device_id: &str) -> anyhow::Result<Vec<Subscription>> {
    let conn = db.lock();
    let mut stmt = conn
        .prepare("SELECT id, endpoint, p256dh, auth FROM push_subscriptions WHERE device_id = ?")?;
    let subs = stmt
        .query_map([device_id], |r| {
            Ok(Subscription {
                id: r.get(0)?,
                endpoint: r.get(1)?,
                p256dh: r.get(2)?,
                auth: r.get(3)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(subs)
}

pub fn record_delivery(db: &Db, sub: &Subscription, result: &Delivery) {
    let conn = db.lock();
    let r = match result {
        Delivery::Sent => conn.execute(
            "UPDATE push_subscriptions SET last_success_at = ?1, failures = 0 WHERE id = ?2",
            params![now_ms(), sub.id],
        ),
        Delivery::Gone => conn.execute("DELETE FROM push_subscriptions WHERE id = ?", [&sub.id]),
        Delivery::Failed(_) => conn.execute(
            "UPDATE push_subscriptions SET failures = failures + 1 WHERE id = ?",
            [&sub.id],
        ),
    };
    if let Err(e) = r {
        tracing::warn!("recording push delivery: {e}");
    }
}

/// Send to many subscriptions concurrently and record the outcomes.
pub async fn fan_out<T: Serialize + Sync>(
    push: &Push,
    db: &Db,
    subs: Vec<Subscription>,
    payload: &T,
    ttl: u32,
    topic: Option<&str>,
) -> usize {
    let results =
        futures_util::future::join_all(subs.iter().map(|s| push.send(s, payload, ttl, topic)))
            .await;
    let mut sent = 0;
    for (sub, result) in subs.iter().zip(results) {
        if let Delivery::Failed(e) = &result {
            tracing::warn!(endpoint = %sub.endpoint.chars().take(60).collect::<String>(), "push failed: {e}");
        }
        if result == Delivery::Sent {
            sent += 1;
        }
        record_delivery(db, sub, &result);
    }
    sent
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Decrypt as a user agent would, to prove the encoding is correct.
    fn decrypt(body: &[u8], ua_secret: &SecretKey, auth: &[u8]) -> Vec<u8> {
        let salt: [u8; 16] = body[..16].try_into().unwrap();
        let idlen = body[20] as usize;
        let as_public = &body[21..21 + idlen];
        let ciphertext = &body[21 + idlen..];
        let shared = p256::ecdh::diffie_hellman(
            ua_secret.to_nonzero_scalar(),
            PublicKey::from_sec1_bytes(as_public).unwrap().as_affine(),
        );
        let ua_public = ua_secret.public_key().to_encoded_point(false);
        let mut key_info = b"WebPush: info\0".to_vec();
        key_info.extend_from_slice(ua_public.as_bytes());
        key_info.extend_from_slice(as_public);
        let mut ikm = [0u8; 32];
        Hkdf::<Sha256>::new(Some(auth), shared.raw_secret_bytes())
            .expand(&key_info, &mut ikm)
            .unwrap();
        let prk = Hkdf::<Sha256>::new(Some(&salt), &ikm);
        let mut cek = [0u8; 16];
        let mut nonce = [0u8; 12];
        prk.expand(b"Content-Encoding: aes128gcm\0", &mut cek)
            .unwrap();
        prk.expand(b"Content-Encoding: nonce\0", &mut nonce)
            .unwrap();
        let mut plain = Aes128Gcm::new_from_slice(&cek)
            .unwrap()
            .decrypt(Nonce::from_slice(&nonce), ciphertext)
            .unwrap();
        assert_eq!(plain.pop(), Some(0x02));
        plain
    }

    #[test]
    fn encrypts_decryptably() {
        let ua_secret = SecretKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
        let ua_public = ua_secret.public_key().to_encoded_point(false);
        let auth = crate::util::random_bytes::<16>();
        let body = encrypt(
            br#"{"hello":"world"}"#,
            &B64URL.encode(ua_public.as_bytes()),
            &B64URL.encode(auth),
        )
        .unwrap();
        assert_eq!(decrypt(&body, &ua_secret, &auth), br#"{"hello":"world"}"#);
    }

    #[test]
    fn vapid_header_is_verifiable() {
        let db = Db::memory().unwrap();
        let push = Push::load(&db, "mailto:x@example.com", true).unwrap();
        let again = Push::load(&db, "mailto:x@example.com", true).unwrap();
        assert_eq!(push.public_key_b64, again.public_key_b64, "key persists");
        let header = push
            .vapid_header("https://fcm.googleapis.com/fcm/send/abc")
            .unwrap();
        let t = header
            .strip_prefix("vapid t=")
            .unwrap()
            .split(", k=")
            .next()
            .unwrap();
        let parts: Vec<&str> = t.split('.').collect();
        let claims: serde_json::Value =
            serde_json::from_slice(&B64URL.decode(parts[1]).unwrap()).unwrap();
        assert_eq!(claims["aud"], "https://fcm.googleapis.com");
        use p256::ecdsa::signature::Verifier;
        let sig = Signature::from_slice(&B64URL.decode(parts[2]).unwrap()).unwrap();
        push.key
            .verifying_key()
            .verify(format!("{}.{}", parts[0], parts[1]).as_bytes(), &sig)
            .unwrap();
    }
}
