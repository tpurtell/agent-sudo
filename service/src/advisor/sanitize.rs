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

/// Redact secrets in free text. Text that looks like a command line also has the
/// arguments that common programs take as passwords removed.
pub fn redact(text: &str) -> String {
    redact_patterns(&redact_words(text))
}

fn redact_patterns(text: &str) -> String {
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

/// Redact the arguments of a command; `command` is the program being run.
pub fn redact_argv(command: Option<&str>, argv: &[String]) -> Vec<String> {
    let mut words: Vec<Word> = command
        .map(|c| Word::plain(basename(c)))
        .into_iter()
        .collect();
    let skip = words.len();
    words.extend(argv.iter().map(|a| Word::plain(a)));
    let hidden = hide(&words);
    argv.iter()
        .zip(hidden.into_iter().skip(skip))
        .map(|(arg, h)| h.unwrap_or_else(|| redact(arg)))
        .collect()
}

const HIDDEN: &str = "[REDACTED]";

/// A shell word with quotes removed, or an operator that separates commands.
struct Word {
    text: String,
    span: (usize, usize),
    op: Option<Op>,
}

#[derive(Clone, Copy, PartialEq)]
enum Op {
    Pipe,
    Sequence,
}

impl Word {
    fn plain(text: &str) -> Word {
        Word {
            text: text.to_string(),
            span: (0, 0),
            op: None,
        }
    }
}

fn basename(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

/// Split text into shell words. It is forgiving: prose with a stray quote just ends up
/// with one long word, which the word rules ignore.
fn tokenize(s: &str) -> Vec<Word> {
    let chars: Vec<(usize, char)> = s.char_indices().collect();
    let at = |i: usize| chars.get(i).map(|&(_, c)| c);
    let pos = |i: usize| chars.get(i).map_or(s.len(), |&(p, _)| p);
    let mut out = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i].1;
        if c.is_whitespace() && c != '\n' {
            i += 1;
            continue;
        }
        let start = i;
        if c == '\n' || c == ';' || c == '|' || (c == '&' && at(i + 1) != Some('>')) {
            while i < chars.len() && i - start < 2 && matches!(chars[i].1, ';' | '|' | '&' | '\n') {
                i += 1;
            }
            let text: String = chars[start..i].iter().map(|&(_, c)| c).collect();
            let op = if text == "|" || text == "|&" {
                Op::Pipe
            } else {
                Op::Sequence
            };
            out.push(Word {
                text,
                span: (pos(start), pos(i)),
                op: Some(op),
            });
            continue;
        }
        if s[pos(i)..].starts_with("<<<") {
            i += 3;
            out.push(Word {
                text: "<<<".into(),
                span: (pos(start), pos(i)),
                op: None,
            });
            continue;
        }
        let mut text = String::new();
        let mut quote = None;
        while let Some(c) = at(i) {
            match quote {
                Some('\'') if c == '\'' => quote = None,
                Some('"') if c == '"' => quote = None,
                Some('"') if c == '\\' && matches!(at(i + 1), Some('"' | '\\' | '$' | '`')) => {
                    i += 1;
                    text.push(chars[i].1);
                }
                Some(_) => text.push(c),
                None if c.is_whitespace()
                    || c == ';'
                    || c == '|'
                    || (c == '&' && !text.ends_with(['>', '<']) && !text.is_empty()) =>
                {
                    break;
                }
                None if c == '\'' || c == '"' => quote = Some(c),
                None if c == '\\' && at(i + 1).is_some() => {
                    i += 1;
                    text.push(chars[i].1);
                }
                None => text.push(c),
            }
            i += 1;
        }
        out.push(Word {
            text,
            span: (pos(start), pos(i)),
            op: None,
        });
    }
    out
}

/// Replace the words of a command line that the word rules hide.
fn redact_words(text: &str) -> String {
    let words = tokenize(text);
    let hidden = hide(&words);
    let mut out = String::with_capacity(text.len());
    let mut last = 0;
    for (w, h) in words.iter().zip(hidden) {
        // A quoted command line, as in `bash -c '…'`, gets the same rules.
        let h = h.or_else(|| {
            let inner = w.text.contains(' ').then(|| redact_words(&w.text))?;
            (inner != w.text).then(|| format!("'{inner}'"))
        });
        if let Some(h) = h {
            out.push_str(&text[last..w.span.0]);
            out.push_str(&h);
            last = w.span.1;
        }
    }
    out.push_str(&text[last..]);
    out
}

/// Which words to hide: values of secret flags, the password arguments of programs
/// that take one on the command line, and what is piped into programs that read one
/// from standard input.
fn hide(words: &[Word]) -> Vec<Option<String>> {
    let mut out = vec![None; words.len()];
    let mut i = 0;
    while i < words.len() {
        // One pipeline: segments separated by `|`, ended by `;`, `&&`, `||` or `&`.
        let mut segments = Vec::new();
        let mut seg_start = i;
        while i < words.len() && words[i].op != Some(Op::Sequence) {
            if words[i].op == Some(Op::Pipe) {
                segments.push(seg_start..i);
                seg_start = i + 1;
            }
            i += 1;
        }
        segments.push(seg_start..i);
        i += 1;
        let mut reads_secret = false;
        for seg in &segments {
            let t: Vec<&str> = words[seg.clone()].iter().map(|w| w.text.as_str()).collect();
            reads_secret |= hide_segment(&t, &mut out[seg.clone()]);
        }
        if reads_secret {
            for seg in segments {
                let t = &words[seg.clone()];
                if let Some(e) = t
                    .iter()
                    .position(|w| matches!(basename(&w.text), "echo" | "printf"))
                {
                    for h in &mut out[seg.start + e + 1..seg.end] {
                        *h = Some(HIDDEN.into());
                    }
                }
            }
        }
    }
    out
}

fn is_flag(w: &str) -> bool {
    w.starts_with('-') && w.len() > 1
}

/// Hide secrets within one simple command. Returns whether it reads a secret from
/// standard input.
fn hide_segment(t: &[&str], out: &mut [Option<String>]) -> bool {
    let mut set = |j: usize, s: String| {
        if j < out.len() {
            out[j] = Some(s);
        }
    };
    let mut reads_secret = t
        .iter()
        .any(|w| matches!(*w, "--password-stdin" | "--with-token"));
    for (i, w) in t.iter().enumerate() {
        if is_secret_flag(w)
            && let Some(v) = t.get(i + 1)
        {
            if !matches!(*w, "-H" | "--header") {
                set(i + 1, HIDDEN.into());
            } else if let Some((name, _)) = v.split_once(':') {
                // `-H "Accept: json"` is harmless; only hide header values that look
                // sensitive. Without a colon it isn't a header (`sudo -H`).
                if KEY_VALUE.is_match(v) || BEARER.is_match(v) {
                    set(i + 1, format!("{name}: {HIDDEN}"));
                }
            }
        }
        if is_flag(w) {
            continue;
        }
        let a = &t[i + 1..];
        let base = i + 1;
        let positional: Vec<usize> = (0..a.len()).filter(|&j| !is_flag(a[j])).collect();
        let has = |f: &str| a.contains(&f);
        // A flag whose following word is secret; a one-letter flag may also carry it
        // attached (`-phunter2`).
        let next = |flags: &[&str], set: &mut dyn FnMut(usize, String)| {
            for (j, x) in a.iter().enumerate() {
                if flags.contains(x) {
                    set(base + j + 1, HIDDEN.into());
                } else if let Some(f) = flags.iter().find(|f| {
                    f.len() == 2 && x.len() > 2 && x.starts_with(**f) && !x.starts_with("--")
                }) {
                    set(base + j, format!("{f}{HIDDEN}"));
                }
            }
        };
        let attached = |prefixes: &[&str], set: &mut dyn FnMut(usize, String)| {
            for (j, x) in a.iter().enumerate() {
                if let Some(p) = prefixes
                    .iter()
                    .find(|p| x.len() > p.len() && x.starts_with(**p))
                {
                    set(base + j, format!("{p}{HIDDEN}"));
                }
            }
        };
        // `user:password` (curl) or `user%password` (Samba) after a flag, or attached.
        let userinfo = |flags: &[&str], sep: char, set: &mut dyn FnMut(usize, String)| {
            let cut = |v: &str| v.split_once(sep).map(|(u, _)| format!("{u}{sep}{HIDDEN}"));
            for (j, x) in a.iter().enumerate() {
                if flags.contains(x) {
                    if let Some(v) = a.get(j + 1).and_then(|v| cut(v)) {
                        set(base + j + 1, v);
                    }
                } else if let Some(f) = flags.iter().find(|f| {
                    f.len() == 2 && x.len() > 2 && x.starts_with(**f) && !x.starts_with("--")
                }) && let Some(v) = cut(&x[2..])
                {
                    set(base + j, format!("{f}{v}"));
                }
            }
        };
        let prog = basename(w);
        match prog {
            "mysql" | "mariadb" | "mysqldump" | "mysqladmin" | "mysqlimport" | "mysqlcheck"
            | "mysqlshow" | "mysqlbinlog" | "mariadb-dump" | "mariadb-admin" => {
                // A bare `-p` prompts; only an attached value is a password.
                attached(&["-p"], &mut set)
            }
            "7z" | "7za" | "7zz" | "7zr" | "rar" | "unrar" => attached(&["-p"], &mut set),
            "xfreerdp" | "wlfreerdp" | "sdl-freerdp" => {
                attached(&["/p:", "/password:", "/gp:"], &mut set)
            }
            "sshpass" | "rdesktop" | "useradd" | "usermod" | "groupadd" | "groupmod" | "az" => {
                next(&["-p"], &mut set)
            }
            "zip" | "unzip" | "ipmitool" | "sqlcmd" | "bcp" => next(&["-P"], &mut set),
            "ssh-keygen" => next(&["-N", "-P"], &mut set),
            "redis-cli" | "valkey-cli" => next(&["-a"], &mut set),
            "ldappasswd" => next(&["-w", "-s", "-a"], &mut set),
            _ if prog.starts_with("ldap") => next(&["-w"], &mut set),
            _ if prog.starts_with("mongo") => next(&["-p"], &mut set),
            "curl" => userinfo(&["-u", "--user", "-U", "--proxy-user"], ':', &mut set),
            "smbclient" | "smbget" | "smbcacls" | "rpcclient" | "net" => {
                userinfo(&["-U", "--user"], '%', &mut set)
            }
            "htpasswd" => {
                let short: Vec<&&str> = a
                    .iter()
                    .filter(|x| is_flag(x) && !x.starts_with("--"))
                    .collect();
                if short.iter().any(|x| x.contains('b'))
                    && let Some(&j) = positional.last()
                {
                    set(base + j, HIDDEN.into());
                }
                reads_secret |= short.iter().any(|x| x.contains('i'));
            }
            "openssl" => {
                next(&["-k", "-K"], &mut set);
                if positional.first().map(|&j| a[j]) == Some("passwd") {
                    for &j in &positional[1..] {
                        if !matches!(a[j - 1], "-salt" | "-in") {
                            set(base + j, HIDDEN.into());
                        }
                    }
                }
                reads_secret |= has("stdin");
            }
            "wpa_passphrase" => {
                if let Some(&j) = positional.get(1) {
                    set(base + j, HIDDEN.into());
                }
            }
            "nmcli" => {
                for (j, x) in a.iter().enumerate() {
                    let x = x.to_ascii_lowercase();
                    if x == "password"
                        || x.ends_with("psk")
                        || x.ends_with(".password")
                        || x.contains("wep-key")
                    {
                        set(base + j + 1, HIDDEN.into());
                    }
                }
            }
            "rabbitmqctl" => {
                if let Some(j) = a
                    .iter()
                    .position(|x| matches!(*x, "add_user" | "change_password"))
                {
                    set(base + j + 2, HIDDEN.into());
                }
            }
            "chpasswd" | "chgpasswd" | "cryptsetup" => reads_secret = true,
            "passwd" => reads_secret |= has("--stdin"),
            "sudo" => reads_secret |= has("-S") || has("--stdin"),
            "smbpasswd" => reads_secret |= has("-s"),
            _ => {}
        }
    }
    if reads_secret && let Some(j) = t.iter().position(|w| *w == "<<<") {
        set(j + 1, HIDDEN.into());
    }
    reads_secret
}

/// A flag whose following argument is a secret.
fn is_secret_flag(arg: &str) -> bool {
    if !arg.starts_with('-') || arg.contains('=') {
        return false;
    }
    if arg == "-H" || arg == "--header" {
        return true;
    }
    let name = arg
        .trim_start_matches('-')
        .to_ascii_lowercase()
        .replace('_', "-");
    // Switches, and flags that say where the secret is rather than what it is.
    if ["no-", "ask-", "prompt-"]
        .iter()
        .any(|p| name.starts_with(p))
        || [
            "-stdin", "-file", "-fd", "-path", "-env", "-command", "-dir",
        ]
        .iter()
        .any(|s| name.ends_with(s))
        || name.ends_with("bypass")
    {
        return false;
    }
    [
        "password",
        "passwd",
        "passphrase",
        "secret",
        "token",
        "credential",
        "api-key",
        "apikey",
        "authkey",
        "auth-key",
        "private-key",
        "access-key",
    ]
    .iter()
    .any(|k| name.contains(k))
        || name.ends_with("pass")
        || ["auth", "key"].contains(&name.as_str())
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
            redact_argv(Some("/usr/bin/tailscale"), &argv),
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

    fn argv(cmd: &str) -> (String, Vec<String>) {
        let mut w = cmd.split(' ').map(str::to_string);
        (format!("/usr/bin/{}", w.next().unwrap()), w.collect())
    }

    #[test]
    fn redacts_passwords_programs_take_as_arguments() {
        for (cmd, secret) in [
            ("mysql -uroot -phunter2 app", "hunter2"),
            ("sshpass -p hunter2 ssh host", "hunter2"),
            ("sshpass -phunter2 ssh host", "hunter2"),
            ("curl -u admin:hunter2 https://x", "hunter2"),
            ("curl -uadmin:hunter2 https://x", "hunter2"),
            ("htpasswd -b /etc/nginx/.htpasswd admin hunter2", "hunter2"),
            (
                "htpasswd -Bbc /etc/nginx/.htpasswd admin hunter2",
                "hunter2",
            ),
            ("openssl passwd -6 -salt abc hunter2", "hunter2"),
            ("smbclient //nas/share -U tj%hunter2", "hunter2"),
            ("usermod -p hunter2 bob", "hunter2"),
            ("redis-cli -a hunter2 ping", "hunter2"),
            ("ldapsearch -D cn=admin -w hunter2 -b dc=x", "hunter2"),
            ("ssh-keygen -t ed25519 -N hunter2 -f key", "hunter2"),
            ("zip -P hunter2 out.zip file", "hunter2"),
            ("7z x -phunter2 a.7z", "hunter2"),
            (
                "ipmitool -I lanplus -H bmc -U admin -P hunter2 power status",
                "hunter2",
            ),
            ("nmcli dev wifi connect home password hunter2", "hunter2"),
            ("nmcli con modify home wifi-sec.psk hunter2", "hunter2"),
            ("wpa_passphrase home hunter2", "hunter2"),
            ("rabbitmqctl add_user bob hunter2", "hunter2"),
            (
                "keytool -importcert -storepass hunter2 -file c.pem",
                "hunter2",
            ),
            ("wget --http-password hunter2 https://x", "hunter2"),
            ("gpg --batch --passphrase hunter2 -d f.gpg", "hunter2"),
        ] {
            let (c, a) = argv(cmd);
            let out = redact_argv(Some(&c), &a).join(" ");
            assert!(!out.contains(secret), "argv {cmd:?} -> {out:?}");
            assert!(out.contains(HIDDEN), "argv {cmd:?} -> {out:?}");
            let out = redact(&format!("sudo {cmd}"));
            assert!(!out.contains(secret), "text {cmd:?} -> {out:?}");
        }
    }

    #[test]
    fn redacts_secrets_in_shell_strings_and_pipes() {
        for (cmd, secret) in [
            (
                "bash -c 'mysql -u root -p\"hunter 2\" -e \"select 1\"'",
                "hunter 2",
            ),
            ("echo 'bob:hunter2' | chpasswd", "hunter2"),
            ("printf '%s\\n' hunter2 | sudo -S apt update", "hunter2"),
            (
                "echo hunter2 | docker login -u me --password-stdin ghcr.io",
                "hunter2",
            ),
            (
                "echo -n hunter2 | cryptsetup luksOpen /dev/sdb1 vault",
                "hunter2",
            ),
            ("chpasswd <<< 'bob:hunter2'", "hunter2"),
            ("cd /srv && sshpass -p 'hunter2' scp f host:", "hunter2"),
        ] {
            let out = redact(cmd);
            assert!(!out.contains(secret), "{cmd:?} -> {out:?}");
            let out = redact_argv(Some("/bin/bash"), &["-c".into(), cmd.into()]).join(" ");
            assert!(!out.contains(secret), "bash -c {cmd:?} -> {out:?}");
        }
    }

    #[test]
    fn keeps_ordinary_command_arguments() {
        for cmd in [
            "psql -h db -U postgres app",
            "mysql -u root -p app",
            "docker login -u me --password-stdin ghcr.io",
            "curl -u admin https://x",
            "apt install mysql-server htpasswd",
            "nvidia-smi -pl 300",
            "passwd bob",
            "echo hello",
            "ssh -p 2222 host",
            "sudo -H pip install x",
        ] {
            let (c, a) = argv(cmd);
            assert_eq!(redact_argv(Some(&c), &a), a, "argv {cmd:?}");
            assert_eq!(redact(cmd), cmd, "text {cmd:?}");
        }
        let s = "grep x f 2>&1 | tee log; echo done & wait";
        assert_eq!(redact(s), s);
    }
}
