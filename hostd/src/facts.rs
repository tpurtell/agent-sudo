//! File facts for the executable and path arguments, gathered by root with `stat`.
//!
//! These close naming loopholes: a renamed shell in a user-writable directory, a
//! doubled slash in `/etc//sudoers`, or a symlink the requester can retarget after
//! approval all look innocent as strings.

use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};

use agent_sudo_protocol::api::{ExecutableFacts, PathFact};

const MAX_ARGS: usize = 128;

/// Who is asking, for writability checks.
pub struct Requester {
    pub uid: u32,
    pub gids: Vec<u32>,
}

impl Requester {
    fn can_write(&self, meta: &std::fs::Metadata) -> bool {
        let mode = meta.mode();
        if meta.uid() == self.uid {
            return true;
        }
        if mode & 0o002 != 0 {
            return true;
        }
        mode & 0o020 != 0 && self.gids.contains(&meta.gid())
    }

    /// Could the requester modify or replace the file at `path`?
    pub fn can_modify(&self, path: &Path) -> bool {
        if std::fs::metadata(path).is_ok_and(|m| self.can_write(&m)) {
            return true;
        }
        // Any writable ancestor directory lets them swap the file or a component out.
        // A sticky directory (like /tmp) only lets its owner or a file's owner do that.
        for dir in path.ancestors().skip(1) {
            let Ok(meta) = std::fs::metadata(dir) else {
                continue;
            };
            if !self.can_write(&meta) {
                continue;
            }
            let sticky = meta.mode() & 0o1000 != 0;
            if !sticky || meta.uid() == self.uid {
                return true;
            }
        }
        false
    }
}

/// Lexically normalise: collapse `.`, `..`, and repeated separators.
pub fn normalize(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for c in path.components() {
        match c {
            Component::ParentDir => {
                out.pop();
            }
            Component::CurDir => {}
            other => out.push(other.as_os_str()),
        }
    }
    out
}

/// Resolve symlinks where the path exists; for a missing final component resolve
/// the parent and append the name.
pub fn resolve(path: &Path) -> PathBuf {
    if let Ok(p) = std::fs::canonicalize(path) {
        return p;
    }
    let norm = normalize(path);
    match (norm.parent(), norm.file_name()) {
        (Some(parent), Some(name)) => std::fs::canonicalize(parent)
            .map(|p| p.join(name))
            .unwrap_or(norm.clone()),
        _ => norm,
    }
}

/// Does any component of `path` pass through a symlink owned by the requester?
fn through_user_symlink(path: &Path, uid: u32) -> bool {
    let mut cur = PathBuf::new();
    for c in normalize(path).components() {
        cur.push(c.as_os_str());
        if let Ok(meta) = std::fs::symlink_metadata(&cur)
            && meta.file_type().is_symlink()
            && meta.uid() == uid
        {
            return true;
        }
    }
    false
}

pub fn executable(command: &str, who: &Requester) -> Option<ExecutableFacts> {
    let path = Path::new(command);
    if !path.is_absolute() {
        return None;
    }
    let real = std::fs::canonicalize(path).ok()?;
    let meta = std::fs::metadata(&real).ok()?;
    Some(ExecutableFacts {
        real_path: real.to_string_lossy().into_owned(),
        owner_uid: meta.uid(),
        mode: meta.mode() & 0o7777,
        writable_by_requester: who.can_modify(&real) || who.can_modify(path),
    })
}

/// Resolve path-like arguments (`/etc/x`, `./x`, `x/y`, `--out=/etc/x`, or a bare
/// name that exists in the working directory).
pub fn paths(args: &[String], base: Option<&Path>, who: &Requester) -> Vec<PathFact> {
    let mut out = Vec::new();
    for (index, arg) in args.iter().enumerate().take(MAX_ARGS) {
        let value = match arg.split_once('=') {
            Some((flag, v)) if flag.starts_with('-') => v,
            _ => arg.as_str(),
        };
        if value.is_empty() || value.len() > 4096 || value.starts_with('-') {
            continue;
        }
        let candidate = Path::new(value);
        let joined = if candidate.is_absolute() {
            candidate.to_path_buf()
        } else if let Some(base) = base {
            base.join(candidate)
        } else {
            continue;
        };
        if !value.contains('/') && std::fs::symlink_metadata(&joined).is_err() {
            continue; // an ordinary word, not a file here
        }
        let resolved = resolve(&joined);
        out.push(PathFact {
            index,
            given: value.to_string(),
            resolved: resolved.to_string_lossy().into_owned(),
            user_symlink: through_user_symlink(&joined, who.uid),
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn me() -> Requester {
        // SAFETY: getuid/getgid have no preconditions.
        let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
        Requester {
            uid,
            gids: vec![gid],
        }
    }

    #[test]
    fn normalises_paths() {
        assert_eq!(
            normalize(Path::new("/etc//./sudoers.d/../sudoers")),
            PathBuf::from("/etc/sudoers")
        );
    }

    #[test]
    fn user_owned_executables_are_writable() {
        let dir = tempfile::tempdir().unwrap();
        let exe = dir.path().join("innocent");
        std::fs::write(&exe, "#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o755)).unwrap();
        let facts = executable(exe.to_str().unwrap(), &me()).unwrap();
        assert!(facts.writable_by_requester);
    }

    #[test]
    fn system_executables_are_not_writable() {
        let who = Requester {
            uid: 12345,
            gids: vec![12345],
        };
        let facts = executable("/bin/sh", &who).unwrap();
        assert!(!facts.writable_by_requester);
        assert!(facts.real_path.starts_with('/'));
    }

    #[test]
    fn resolves_arguments_and_flags_user_symlinks() {
        let dir = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink("/etc/hostname", dir.path().join("link")).unwrap();
        std::fs::write(dir.path().join("plain"), "x").unwrap();
        let args: Vec<String> = [
            "-y",
            "link",
            "plain",
            "word",
            "--out=/etc//passwd",
            "./missing",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let facts = paths(&args, Some(dir.path()), &me());
        let get = |i: usize| facts.iter().find(|f| f.index == i);
        assert!(get(0).is_none());
        assert!(get(1).unwrap().user_symlink);
        assert!(
            get(1).unwrap().resolved.ends_with("hostname")
                || get(1).unwrap().resolved.contains("/etc/")
        );
        assert!(!get(2).unwrap().user_symlink);
        assert!(get(3).is_none());
        assert_eq!(get(4).unwrap().resolved, "/etc/passwd");
        assert!(get(5).unwrap().resolved.ends_with("/missing"));
    }
}
