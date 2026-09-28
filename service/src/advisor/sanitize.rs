//! Redact secrets before anything is sent to a model.
//!
//! The approver always sees the real command in the UI; only the advisor input is
//! redacted. The rules are deliberately greedy: a false positive costs the model a
//! little context, a false negative leaks a credential to a third party.

use std::sync::LazyLock;

use regex::Regex;

const SENSITIVE: &str = r"(?i)(pass(word|wd)?|pwd|secret|token|api[_-]?key|apikey|auth(orization)?|credential|private[_-]?key|access[_-]?key|session|cookie|signature|sig|client[_-]?secret|bearer)";

static KEY_VALUE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(&format!(
        r"(?P<k>[A-Za-z0-9_.-]*{SENSITIVE}[A-Za-z0-9_.-]*)(?P<sep>\s*[=:]\s*)(?P<v>[^\s&,;]+)"
    ))
    .unwrap()
});
static URL_USERINFO: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?P<scheme>[a-zA-Z][a-zA-Z0-9+.-]*://)(?P<user>[^/:@\s]+):(?P<pw>[^@/\s]+)@")
        .unwrap()
});
static BEARER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\b(bearer|basic|token)\s+[A-Za-z0-9._~+/=-]{8,}").unwrap());
static KNOWN_TOKENS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r"(sk-[A-Za-z0-9_-]{10,}|sk_(live|test)_[A-Za-z0-9]{10,}|gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}",
        r"|xox[abprs]-[A-Za-z0-9-]{10,}|AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{30,}|glpat-[A-Za-z0-9_-]{16,}",
        r"|tskey-[A-Za-z0-9-]{10,}|eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}|hf_[A-Za-z0-9]{20,}|npm_[A-Za-z0-9]{30,})"
    ))
    .unwrap()
});
static PEM: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(-----END [A-Z ]*PRIVATE KEY-----|$)")
        .unwrap()
});
static HIGH_ENTROPY: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"[A-Za-z0-9+/_=-]{32,}").unwrap());

fn looks_random(s: &str) -> bool {
    let upper = s.chars().any(|c| c.is_ascii_uppercase());
    let lower = s.chars().any(|c| c.is_ascii_lowercase());
    let digit = s.chars().any(|c| c.is_ascii_digit());
    let hexish = s.chars().all(|c| c.is_ascii_hexdigit());
    // Paths and package names have separators and words; tokens mix classes densely.
    (upper && lower && digit) || (hexish && s.len() >= 40)
}

/// Redact secrets in free text.
pub fn redact(text: &str) -> String {
    let s = PEM.replace_all(text, "[REDACTED PRIVATE KEY]");
    let s = URL_USERINFO.replace_all(&s, "${scheme}${user}:[REDACTED]@");
    let s = BEARER.replace_all(&s, "$1 [REDACTED]");
    let s = KNOWN_TOKENS.replace_all(&s, "[REDACTED]");
    let s = KEY_VALUE.replace_all(&s, "${k}${sep}[REDACTED]");
    let s = HIGH_ENTROPY.replace_all(&s, |caps: &regex::Captures| {
        let m = &caps[0];
        if looks_random(m) {
            "[REDACTED]".to_string()
        } else {
            m.to_string()
        }
    });
    s.into_owned()
}

fn is_secret_flag(arg: &str) -> bool {
    let name = arg.trim_start_matches('-').to_ascii_lowercase();
    arg.starts_with('-')
        && !arg.contains('=')
        && [
            "password",
            "passwd",
            "pass",
            "token",
            "secret",
            "api-key",
            "apikey",
            "api_key",
            "auth",
            "authkey",
            "auth-key",
            "client-secret",
            "private-key",
            "key",
            "access-key",
            "secret-key",
            "credentials",
            "header",
            "h",
        ]
        .contains(&name.as_str())
}

/// Redact an argument vector; values following secret-bearing flags are removed too.
pub fn redact_argv(argv: &[String]) -> Vec<String> {
    let mut out = Vec::with_capacity(argv.len());
    let mut hide_next = false;
    for arg in argv {
        if hide_next {
            // `-H "Accept: json"` is harmless; only hide header values that look sensitive.
            out.push(
                if arg.contains(':') && !KEY_VALUE.is_match(arg) && !BEARER.is_match(arg) {
                    redact(arg)
                } else {
                    "[REDACTED]".to_string()
                },
            );
            hide_next = false;
            continue;
        }
        hide_next = is_secret_flag(arg);
        out.push(redact(arg));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_common_secrets() {
        let cases = [
            (
                "curl -H 'Authorization: Bearer abcdefghijklmnop' x",
                "Authorization: [REDACTED]",
            ),
            (
                "https://bob:hunter2@example.com/x",
                "https://bob:[REDACTED]@example.com/x",
            ),
            (
                "OPENAI_API_KEY=sk-proj-abcdefghijklmnopqrstuv",
                "OPENAI_API_KEY=[REDACTED]",
            ),
            ("token ghp_abcdefghijklmnopqrstuvwxyz0123", "[REDACTED]"),
            ("--password=letmein", "--password=[REDACTED]"),
            (
                "https://x.s3.amazonaws.com/f?X-Amz-Signature=abc123def&x=1",
                "X-Amz-Signature=[REDACTED]",
            ),
            (
                "tailscale up --authkey tskey-auth-kAbCdEf123456-XYZ",
                "[REDACTED]",
            ),
        ];
        for (input, needle) in cases {
            let out = redact(input);
            assert!(out.contains(needle), "{input:?} -> {out:?}");
            for secret in [
                "abcdefghijklmnop",
                "hunter2",
                "abcdefghijklmnopqrstuv",
                "letmein",
                "abc123def",
                "kAbCdEf123456",
            ] {
                assert!(!out.contains(secret), "{input:?} leaked {secret}: {out:?}");
            }
        }
    }

    #[test]
    fn keeps_ordinary_text() {
        for s in [
            "/usr/bin/apt install linux-headers-6.17.0-1032-nvidia",
            "systemctl restart nvidia-persistenced.service",
            "/home/tj/Developer/some-project-with-a-long-name/build",
            "Restarting the daemon after changing the GPU configuration",
        ] {
            assert_eq!(redact(s), s);
        }
    }

    #[test]
    fn redacts_values_after_flags() {
        let argv: Vec<String> = [
            "up",
            "--authkey",
            "abc123",
            "--hostname",
            "moa",
            "-H",
            "Accept: application/json",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        assert_eq!(
            redact_argv(&argv),
            vec![
                "up",
                "--authkey",
                "[REDACTED]",
                "--hostname",
                "moa",
                "-H",
                "Accept: application/json"
            ]
        );
    }

    #[test]
    fn redacts_private_keys_and_random_strings() {
        assert_eq!(
            redact("-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----"),
            "[REDACTED PRIVATE KEY]"
        );
        assert_eq!(
            redact("x Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MEFCQ0RFRg y"),
            "x [REDACTED] y"
        );
    }
}
