//! Line codec for the root-only socket between `agent-sudo` and `agent-sudo-hostd`.
//!
//! The setuid binary may not take new dependencies, so the protocol is deliberately
//! trivial: ASCII lines of `verb key=value key=value`, where every value is
//! percent-encoded. A request is a block of `key=value` lines ended by an empty line.
//! The same codec (and the same test vectors) lives in the `agent-sudo-protocol` crate.
#![forbid(unsafe_code)]

/// Bytes that are passed through unencoded.
fn is_plain(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"-._~/:@,+".contains(&b)
}

pub(crate) fn encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(bytes.len());
    for &b in bytes {
        if is_plain(b) {
            out.push(b as char);
        } else {
            out.push('%');
            out.push(HEX[(b >> 4) as usize] as char);
            out.push(HEX[(b & 0xf) as usize] as char);
        }
    }
    out
}

pub(crate) fn decode(s: &str) -> Option<Vec<u8>> {
    fn hex(b: u8) -> Option<u8> {
        match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            b'A'..=b'F' => Some(b - b'A' + 10),
            _ => None,
        }
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' => {
                let hi = hex(*bytes.get(i + 1)?)?;
                let lo = hex(*bytes.get(i + 2)?)?;
                out.push(hi << 4 | lo);
                i += 3;
            }
            b if is_plain(b) => {
                out.push(b);
                i += 1;
            }
            _ => return None,
        }
    }
    Some(out)
}

/// One `verb key=value ...` line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Line {
    pub verb: String,
    pub fields: Vec<(String, Vec<u8>)>,
}

impl Line {
    pub(crate) fn parse(line: &str) -> Option<Line> {
        let mut parts = line.trim_end_matches(['\r', '\n']).split(' ');
        let verb = parts.next().filter(|v| !v.is_empty())?.to_string();
        if !verb.bytes().all(|b| b.is_ascii_lowercase() || b == b'-') {
            return None;
        }
        let mut fields = Vec::new();
        for part in parts.filter(|p| !p.is_empty()) {
            let (k, v) = part.split_once('=')?;
            fields.push((k.to_string(), decode(v)?));
        }
        Some(Line { verb, fields })
    }

    pub(crate) fn get(&self, key: &str) -> Option<&[u8]> {
        self.fields
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_slice())
    }

    pub(crate) fn get_str(&self, key: &str) -> Option<String> {
        self.get(key)
            .map(|v| String::from_utf8_lossy(v).into_owned())
    }

    pub(crate) fn flag(&self, key: &str) -> bool {
        self.get(key) == Some(b"1")
    }
}

/// Builder for a request block.
#[derive(Default)]
pub(crate) struct RequestBlock {
    buf: String,
}

impl RequestBlock {
    pub(crate) fn new() -> Self {
        let mut block = Self::default();
        block.buf.push_str("agent-sudo-request v=1\n");
        block
    }

    pub(crate) fn field(&mut self, key: &str, value: impl AsRef<[u8]>) -> &mut Self {
        debug_assert!(key.bytes().all(|b| b.is_ascii_lowercase() || b == b'_'));
        self.buf.push_str(key);
        self.buf.push('=');
        self.buf.push_str(&encode(value.as_ref()));
        self.buf.push('\n');
        self
    }

    pub(crate) fn finish(mut self) -> String {
        self.buf.push('\n');
        self.buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_arbitrary_bytes() {
        let all: Vec<u8> = (0..=255).collect();
        assert_eq!(decode(&encode(&all)).unwrap(), all);
    }

    #[test]
    fn shared_vectors() {
        // Keep in sync with protocol/src/wire.rs
        assert_eq!(encode(b"apt install -y foo"), "apt%20install%20-y%20foo");
        assert_eq!(encode(b"a=b\nc"), "a%3Db%0Ac");
        assert_eq!(encode("é".as_bytes()), "%C3%A9");
        assert_eq!(encode(b"/usr/bin/x@1,2+3~_."), "/usr/bin/x@1,2+3~_.");
    }

    #[test]
    fn rejects_malformed() {
        assert!(decode("%4").is_none());
        assert!(decode("%zz").is_none());
        assert!(decode("a b").is_none());
        assert!(Line::parse("Approved x=1").is_none());
        assert!(Line::parse("approved novalue").is_none());
    }

    #[test]
    fn parses_lines() {
        let line = Line::parse("approved by=tj via=user label=iPhone%2015 refresh=1\n").unwrap();
        assert_eq!(line.verb, "approved");
        assert_eq!(line.get_str("label").unwrap(), "iPhone 15");
        assert!(line.flag("refresh"));
        assert!(!line.flag("hard"));
    }
}
