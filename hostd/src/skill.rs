//! `agent-sudo-hostd skill`: install the optional agent skill for coding agents.
//!
//! Most agents read the shared `~/.agents/skills/`; a few only read their own folder.
//! The skill is written to the shared folder plus a copy for each detected agent that
//! needs its own. Copies rather than symlinks: symlinked skill folders are not
//! documented as supported by most agents. Re-run after upgrading to refresh them.

use std::io::{BufRead, IsTerminal, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

pub const SKILL: &str = include_str!("../../skills/agent-sudo/SKILL.md");
const NAME: &str = "agent-sudo";

/// Where an agent looks for user-global skills.
enum Reads {
    /// The shared `~/.agents/skills` (possibly among others).
    Shared,
    /// Only its own folder(s), relative to `$HOME`.
    Own(&'static [&'static str]),
}

struct Agent {
    name: &'static str,
    /// Config directories (relative to `$HOME`) whose presence means it is installed.
    dirs: &'static [&'static str],
    /// Executable names on `$PATH`.
    bins: &'static [&'static str],
    reads: Reads,
}

// Sources: each agent's skills documentation (September 2026); see docs/AGENTS.md.
const AGENTS: &[Agent] = &[
    Agent {
        name: "Claude Code",
        dirs: &[".claude"],
        bins: &["claude"],
        reads: Reads::Own(&[".claude/skills"]),
    },
    Agent {
        name: "OpenAI Codex",
        dirs: &[".codex"],
        bins: &["codex"],
        reads: Reads::Shared,
    },
    Agent {
        name: "Gemini CLI",
        dirs: &[".gemini"],
        bins: &["gemini"],
        reads: Reads::Shared,
    },
    Agent {
        name: "GitHub Copilot CLI",
        dirs: &[".copilot"],
        bins: &["copilot"],
        reads: Reads::Shared,
    },
    Agent {
        name: "Cursor",
        dirs: &[".cursor"],
        bins: &["cursor-agent", "cursor"],
        reads: Reads::Shared,
    },
    Agent {
        name: "opencode",
        dirs: &[".config/opencode"],
        bins: &["opencode"],
        reads: Reads::Shared,
    },
    Agent {
        name: "Goose",
        dirs: &[".config/goose"],
        bins: &["goose"],
        reads: Reads::Shared,
    },
    Agent {
        name: "Amp",
        dirs: &[".config/amp"],
        bins: &["amp"],
        reads: Reads::Shared,
    },
    Agent {
        name: "Grok CLI",
        dirs: &[".grok"],
        bins: &["grok"],
        reads: Reads::Own(&[".grok/skills"]),
    },
    Agent {
        name: "Qwen Code",
        dirs: &[".qwen"],
        bins: &["qwen"],
        reads: Reads::Own(&[".qwen/skills"]),
    },
    Agent {
        name: "Crush",
        dirs: &[".config/crush"],
        bins: &["crush"],
        reads: Reads::Shared,
    },
    Agent {
        name: "Factory Droid",
        dirs: &[".factory"],
        bins: &["droid"],
        reads: Reads::Shared,
    },
    Agent {
        name: "Cline",
        dirs: &[".cline"],
        bins: &["cline"],
        reads: Reads::Own(&[".cline/skills"]),
    },
    Agent {
        name: "Kilo Code",
        dirs: &[".kilo"],
        bins: &["kilo"],
        reads: Reads::Shared,
    },
    Agent {
        name: "Devin Desktop / Windsurf",
        dirs: &[".config/devin", ".codeium/windsurf"],
        bins: &["devin", "windsurf"],
        reads: Reads::Shared,
    },
    Agent {
        name: "Kiro",
        dirs: &[".kiro"],
        bins: &["kiro", "kiro-cli"],
        reads: Reads::Own(&[".kiro/skills"]),
    },
    Agent {
        name: "Augment (Auggie)",
        dirs: &[".augment"],
        bins: &["auggie"],
        reads: Reads::Shared,
    },
    Agent {
        name: "OpenHands",
        dirs: &[".openhands"],
        bins: &["openhands"],
        reads: Reads::Shared,
    },
    Agent {
        name: "Mistral Vibe",
        dirs: &[".vibe"],
        bins: &["vibe"],
        reads: Reads::Shared,
    },
    Agent {
        name: "Junie",
        dirs: &[".junie"],
        bins: &["junie"],
        reads: Reads::Shared,
    },
    Agent {
        name: "Trae",
        dirs: &[".trae", ".trae-cn"],
        bins: &["trae"],
        reads: Reads::Own(&[".trae/skills", ".trae-cn/skills"]),
    },
    Agent {
        name: "Zed",
        dirs: &[".config/zed"],
        bins: &["zed"],
        reads: Reads::Shared,
    },
    Agent {
        name: "Google Antigravity",
        dirs: &[".gemini/antigravity", ".gemini/config"],
        bins: &["antigravity"],
        reads: Reads::Own(&[".gemini/config/skills"]),
    },
];

const SHARED: &str = ".agents/skills";

fn on_path(bin: &str) -> bool {
    std::env::var_os("PATH")
        .map(|p| std::env::split_paths(&p).any(|d| d.join(bin).is_file()))
        .unwrap_or(false)
}

struct Plan {
    detected: Vec<&'static str>,
    targets: Vec<PathBuf>,
}

fn plan(home: &Path) -> Plan {
    let mut detected = Vec::new();
    let mut targets = Vec::new();
    let mut shared = false;
    for a in AGENTS {
        let present =
            a.dirs.iter().any(|d| home.join(d).exists()) || a.bins.iter().any(|b| on_path(b));
        if !present {
            continue;
        }
        detected.push(a.name);
        match &a.reads {
            Reads::Shared => shared = true,
            Reads::Own(dirs) => {
                // Trae has regional variants: only write where that variant exists.
                let existing: Vec<_> = dirs
                    .iter()
                    .filter(|d| home.join(d).parent().is_some_and(|p| p.exists()))
                    .collect();
                let pick = if existing.is_empty() {
                    vec![&dirs[0]]
                } else {
                    existing
                };
                targets.extend(pick.into_iter().map(|d| home.join(d).join(NAME)));
            }
        }
    }
    // Older Codex builds read ~/.codex/skills; refresh it when that folder exists.
    if home.join(".codex/skills").is_dir() {
        targets.push(home.join(".codex/skills").join(NAME));
    }
    if shared || detected.is_empty() {
        targets.insert(0, home.join(SHARED).join(NAME));
    }
    targets.dedup();
    Plan { detected, targets }
}

fn home() -> Result<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .context("HOME is not set")
}

fn confirm(prompt: &str) -> Result<bool> {
    print!("{prompt} [Y/n] ");
    std::io::stdout().flush()?;
    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line)?;
    Ok(!matches!(line.trim().to_lowercase().as_str(), "n" | "no"))
}

pub fn install(yes: bool, dry_run: bool) -> Result<()> {
    let home = home()?;
    let p = plan(&home);
    if p.detected.is_empty() {
        println!("No known coding agents found; installing to the shared ~/{SHARED} only.");
    } else {
        println!("Found: {}", p.detected.join(", "));
    }
    println!("The agent-sudo skill will be written to:");
    for t in &p.targets {
        println!("  {}", t.join("SKILL.md").display());
    }
    if dry_run {
        return Ok(());
    }
    if !yes && std::io::stdin().is_terminal() && !confirm("Install?")? {
        println!("Nothing changed.");
        return Ok(());
    }
    for t in &p.targets {
        std::fs::create_dir_all(t).with_context(|| format!("creating {}", t.display()))?;
        std::fs::write(t.join("SKILL.md"), SKILL)
            .with_context(|| format!("writing {}", t.display()))?;
    }
    println!("Installed. Agents pick it up in new sessions; re-run after upgrading agent-sudo.");
    Ok(())
}

fn all_locations(home: &Path) -> Vec<PathBuf> {
    let mut v = vec![
        home.join(SHARED).join(NAME),
        home.join(".codex/skills").join(NAME),
    ];
    for a in AGENTS {
        if let Reads::Own(dirs) = &a.reads {
            v.extend(dirs.iter().map(|d| home.join(d).join(NAME)));
        }
    }
    v
}

/// Only folders that hold our skill (and nothing else) are removed.
fn ours(dir: &Path) -> bool {
    std::fs::read_dir(dir).is_ok_and(|entries| {
        let names: Vec<_> = entries
            .filter_map(|e| e.ok())
            .map(|e| e.file_name())
            .collect();
        names.len() == 1 && names[0] == "SKILL.md"
    }) && std::fs::read_to_string(dir.join("SKILL.md"))
        .is_ok_and(|s| s.contains("name: agent-sudo"))
}

pub fn remove() -> Result<()> {
    let home = home()?;
    let mut removed = 0;
    for dir in all_locations(&home) {
        if ours(&dir) {
            std::fs::remove_dir_all(&dir)?;
            println!("removed {}", dir.display());
            removed += 1;
        }
    }
    if removed == 0 {
        println!("The agent-sudo skill is not installed.");
    }
    Ok(())
}

pub fn status() -> Result<()> {
    let home = home()?;
    let p = plan(&home);
    println!(
        "Agents found: {}",
        if p.detected.is_empty() {
            "none".into()
        } else {
            p.detected.join(", ")
        }
    );
    for dir in all_locations(&home) {
        let file = dir.join("SKILL.md");
        let state = match std::fs::read_to_string(&file) {
            Ok(s) if s == SKILL => "installed",
            Ok(_) => "outdated (run `agent-sudo-hostd skill install`)",
            Err(_) if p.targets.contains(&dir) => "missing",
            Err(_) => continue,
        };
        println!("  {state:<10} {}", file.display());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plans_shared_plus_own_folders() {
        let home = tempfile::tempdir().unwrap();
        for d in [".claude", ".codex/skills", ".grok", ".config/opencode"] {
            std::fs::create_dir_all(home.path().join(d)).unwrap();
        }
        let p = plan(home.path());
        let rel: Vec<String> = p
            .targets
            .iter()
            .map(|t| t.strip_prefix(home.path()).unwrap().display().to_string())
            .collect();
        assert_eq!(rel[0], ".agents/skills/agent-sudo");
        assert!(rel.contains(&".claude/skills/agent-sudo".into()));
        assert!(rel.contains(&".grok/skills/agent-sudo".into()));
        assert!(rel.contains(&".codex/skills/agent-sudo".into()));
        assert!(!rel.iter().any(|r| r.contains(".qwen")));
    }

    #[test]
    fn remove_only_touches_our_folders() {
        let home = tempfile::tempdir().unwrap();
        let ours_dir = home.path().join(".agents/skills/agent-sudo");
        std::fs::create_dir_all(&ours_dir).unwrap();
        std::fs::write(ours_dir.join("SKILL.md"), SKILL).unwrap();
        let theirs = home.path().join(".claude/skills/agent-sudo");
        std::fs::create_dir_all(&theirs).unwrap();
        std::fs::write(theirs.join("SKILL.md"), "name: agent-sudo").unwrap();
        std::fs::write(theirs.join("notes.md"), "user file").unwrap();
        assert!(ours(&ours_dir));
        assert!(!ours(&theirs));
    }
}
