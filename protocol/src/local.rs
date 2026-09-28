//! The request block the setuid binary sends to hostd, decoded.

use crate::wire::parse_block;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LocalRequest {
    pub mode: String,
    pub nonblocking: bool,
    pub interactive: bool,
    pub pid: u32,
    pub hostname: String,
    pub user: String,
    pub uid: u32,
    pub gid: u32,
    pub target_user: String,
    pub target_uid: u32,
    pub target_group: Option<String>,
    pub target_gid: u32,
    pub timeout_secs: u64,
    pub launch: String,
    pub command: Option<Vec<u8>>,
    pub args: Vec<Vec<u8>>,
    pub chdir: Option<Vec<u8>>,
    pub cwd: Option<Vec<u8>>,
    pub tty: Option<String>,
    pub context: Option<String>,
    pub session: Option<String>,
    /// Environment overrides from the command line, as `NAME=value`.
    pub env: Vec<Vec<u8>>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum LocalRequestError {
    #[error("malformed request block")]
    Malformed,
    #[error("missing field {0}")]
    Missing(&'static str),
    #[error("invalid field {0}")]
    Invalid(&'static str),
}

fn text(v: &[u8]) -> String {
    String::from_utf8_lossy(v).into_owned()
}

impl LocalRequest {
    pub fn parse(block: &str) -> Result<LocalRequest, LocalRequestError> {
        let fields = parse_block(block).ok_or(LocalRequestError::Malformed)?;
        let mut req = LocalRequest::default();
        let mut seen_uid = false;
        let mut seen_target = false;
        for (key, value) in fields {
            let num = |name: &'static str| -> Result<u64, LocalRequestError> {
                std::str::from_utf8(&value)
                    .ok()
                    .and_then(|s| s.parse().ok())
                    .ok_or(LocalRequestError::Invalid(name))
            };
            match key.as_str() {
                "mode" => req.mode = text(&value),
                "nonblocking" => req.nonblocking = value == b"1",
                "interactive" => req.interactive = value == b"1",
                "pid" => req.pid = num("pid")? as u32,
                "hostname" => req.hostname = text(&value),
                "user" => req.user = text(&value),
                "uid" => {
                    req.uid = num("uid")? as u32;
                    seen_uid = true;
                }
                "gid" => req.gid = num("gid")? as u32,
                "target_user" => req.target_user = text(&value),
                "target_uid" => {
                    req.target_uid = num("target_uid")? as u32;
                    seen_target = true;
                }
                "target_group" => req.target_group = Some(text(&value)),
                "target_gid" => req.target_gid = num("target_gid")? as u32,
                "timeout_secs" => req.timeout_secs = num("timeout_secs")?,
                "launch" => req.launch = text(&value),
                "command" => req.command = Some(value),
                "arg" => req.args.push(value),
                "chdir" => req.chdir = Some(value),
                "cwd" => req.cwd = Some(value),
                "tty" => req.tty = Some(text(&value)),
                "context" => req.context = Some(text(&value)),
                "session" => req.session = Some(text(&value)),
                "env" => req.env.push(value),
                // Forward compatibility: newer binaries may send more fields.
                _ => {}
            }
        }
        if !matches!(req.mode.as_str(), "run" | "edit" | "list" | "validate") {
            return Err(LocalRequestError::Invalid("mode"));
        }
        if !seen_uid {
            return Err(LocalRequestError::Missing("uid"));
        }
        if !seen_target {
            return Err(LocalRequestError::Missing("target_uid"));
        }
        if req.pid == 0 {
            return Err(LocalRequestError::Missing("pid"));
        }
        Ok(req)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_full_request() {
        let block = "agent-sudo-request v=1\nmode=run\nnonblocking=0\ninteractive=1\npid=42\nhostname=moa\nuser=tj\nuid=1000\ngid=1000\ntarget_user=root\ntarget_uid=0\ntarget_gid=0\ntimeout_secs=600\nlaunch=direct\ncommand=/usr/bin/apt\narg=install\narg=-y\ncwd=/home/tj\ncontext=Install%20headers\nfuture=ignored\n\n";
        let req = LocalRequest::parse(block).unwrap();
        assert_eq!(req.pid, 42);
        assert_eq!(req.command.as_deref(), Some(&b"/usr/bin/apt"[..]));
        assert_eq!(req.args, vec![b"install".to_vec(), b"-y".to_vec()]);
        assert_eq!(req.context.as_deref(), Some("Install headers"));
        assert!(req.interactive);
    }

    #[test]
    fn rejects_missing_identity() {
        let block = "agent-sudo-request v=1\nmode=run\npid=1\ntarget_uid=0\n\n";
        assert_eq!(
            LocalRequest::parse(block),
            Err(LocalRequestError::Missing("uid"))
        );
        let block = "agent-sudo-request v=1\nmode=nope\npid=1\nuid=1\ntarget_uid=0\n\n";
        assert_eq!(
            LocalRequest::parse(block),
            Err(LocalRequestError::Invalid("mode"))
        );
    }
}
