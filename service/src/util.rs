//! Small helpers: time, identifiers, tokens.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest, Sha256};

/// Milliseconds since the Unix epoch.
pub fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

pub fn now_secs() -> i64 {
    now_ms() / 1000
}

/// Prefixed, sortable identifier, e.g. `req_01K...`.
pub fn new_id(prefix: &str) -> String {
    format!("{prefix}_{}", ulid::Ulid::new().to_string().to_lowercase())
}

pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut buf = [0u8; N];
    getrandom::fill(&mut buf).expect("operating system RNG unavailable");
    buf
}

/// 256-bit URL-safe token. Never starts with `-`, so pasted onto a command line it
/// can't be read as an option.
pub fn new_token() -> String {
    loop {
        let t = URL_SAFE_NO_PAD.encode(random_bytes::<32>());
        if !t.starts_with('-') {
            return t;
        }
    }
}

pub fn sha256_hex(data: impl AsRef<[u8]>) -> String {
    hex::encode(Sha256::digest(data.as_ref()))
}

/// Short human code (Crockford base32 without ambiguous letters), e.g. `K7QX`.
pub fn short_code() -> String {
    const ALPHABET: &[u8] = b"23456789ABCDEFGHJKMNPQRSTVWXYZ";
    random_bytes::<4>()
        .iter()
        .map(|b| ALPHABET[*b as usize % ALPHABET.len()] as char)
        .collect()
}

/// Constant-time comparison for secrets.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

pub fn human_duration(secs: i64) -> String {
    let secs = secs.max(0);
    if secs < 90 {
        format!("{secs}s")
    } else if secs < 90 * 60 {
        format!("{}m", (secs + 30) / 60)
    } else if secs < 36 * 3600 {
        let h = secs / 3600;
        let m = (secs % 3600 + 30) / 60;
        if m == 0 {
            format!("{h}h")
        } else {
            format!("{h}h {m}m")
        }
    } else {
        format!("{}d", (secs + 43200) / 86400)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_and_codes() {
        assert!(new_id("req").starts_with("req_"));
        assert_eq!(short_code().len(), 4);
        assert_eq!(new_token().len(), 43);
        assert!((0..2000).all(|_| !new_token().starts_with('-')));
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"ab"));
    }

    #[test]
    fn durations() {
        assert_eq!(human_duration(45), "45s");
        assert_eq!(human_duration(30 * 60), "30m");
        assert_eq!(human_duration(3600 * 2 + 60 * 15), "2h 15m");
        assert_eq!(human_duration(86400 * 3), "3d");
    }
}
