//! Percent-encoded line codec. Keep in sync with `sudo/src/sudo/agent/wire.rs`;
//! both carry the same test vectors.

fn is_plain(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"-._~/:@,+".contains(&b)
}

pub fn encode(bytes: &[u8]) -> String {
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

pub fn decode(s: &str) -> Option<Vec<u8>> {
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
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Line {
    pub verb: String,
    pub fields: Vec<(String, Vec<u8>)>,
}

impl Line {
    pub fn new(verb: &str) -> Self {
        Line {
            verb: verb.to_string(),
            fields: Vec::new(),
        }
    }

    pub fn with(mut self, key: &str, value: impl AsRef<[u8]>) -> Self {
        self.fields.push((key.to_string(), value.as_ref().to_vec()));
        self
    }

    pub fn parse(line: &str) -> Option<Line> {
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

    pub fn render(&self) -> String {
        let mut out = self.verb.clone();
        for (k, v) in &self.fields {
            out.push(' ');
            out.push_str(k);
            out.push('=');
            out.push_str(&encode(v));
        }
        out.push('\n');
        out
    }

    pub fn get(&self, key: &str) -> Option<&[u8]> {
        self.fields
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_slice())
    }

    pub fn get_str(&self, key: &str) -> Option<String> {
        self.get(key)
            .map(|v| String::from_utf8_lossy(v).into_owned())
    }
}

/// Parse a request block: a header line followed by `key=value` lines, ended by an
/// empty line. Returns the ordered key/value pairs.
pub fn parse_block(text: &str) -> Option<Vec<(String, Vec<u8>)>> {
    // The block must be terminated by an empty line.
    let end = text.find("\n\n")?;
    let mut lines = text[..end + 1].split('\n');
    let header = Line::parse(lines.next()?)?;
    if header.verb != "agent-sudo-request" || header.get("v") != Some(b"1") {
        return None;
    }
    let mut out = Vec::new();
    for line in lines {
        if line.is_empty() {
            return Some(out);
        }
        let (k, v) = line.split_once('=')?;
        if k.is_empty() || !k.bytes().all(|b| b.is_ascii_lowercase() || b == b'_') {
            return None;
        }
        out.push((k.to_string(), decode(v)?));
    }
    None
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
        // Keep in sync with sudo/src/sudo/agent/wire.rs
        assert_eq!(encode(b"apt install -y foo"), "apt%20install%20-y%20foo");
        assert_eq!(encode(b"a=b\nc"), "a%3Db%0Ac");
        assert_eq!(encode("é".as_bytes()), "%C3%A9");
        assert_eq!(encode(b"/usr/bin/x@1,2+3~_."), "/usr/bin/x@1,2+3~_.");
    }

    #[test]
    fn line_roundtrip() {
        let line = Line::new("approved")
            .with("by", "tj")
            .with("label", "iPhone 15 · Safari");
        assert_eq!(Line::parse(&line.render()).unwrap(), line);
    }

    #[test]
    fn parses_block() {
        let block = "agent-sudo-request v=1\nmode=run\narg=-y\narg=foo%20bar\n\n";
        let fields = parse_block(block).unwrap();
        assert_eq!(fields.len(), 3);
        assert_eq!(fields[2].1, b"foo bar");
        assert!(parse_block("agent-sudo-request v=2\n\n").is_none());
        assert!(parse_block("agent-sudo-request v=1\nmode=run\n").is_none());
        assert!(parse_block("agent-sudo-request v=1\nBAD=x\n\n").is_none());
    }
}
