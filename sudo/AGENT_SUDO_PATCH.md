# agent-sudo patch inventory

This directory is a `git subtree` of [sudo-rs](https://github.com/trifectatechfoundation/sudo-rs)
(currently **v0.2.15**) with a small, feature-gated patch. Built without
`--features agent-approval`, the code paths are upstream sudo-rs.

Update procedure:

```sh
git subtree pull --prefix sudo https://github.com/trifectatechfoundation/sudo-rs.git vX.Y.Z --squash
# resolve conflicts using the list below, then:
cargo test --features agent-approval && cargo test
```

## New files (ours)

| File | Purpose |
| --- | --- |
| `src/sudo/agent/mod.rs` | Orchestration: consult hostd once sudoers requires authentication; race the password prompt; map decisions to outcomes. |
| `src/sudo/agent/client.rs` | Unix socket client for `agent-sudo-hostd`; refuses peers that are not uid 0. |
| `src/sudo/agent/wire.rs` | Percent-encoded line codec (shared test vectors with `protocol/`). |
| `src/sudo/agent/config.rs` | `/etc/agent-sudo/client.conf` parser; absent file = broker disabled. |
| `src/sudo/agent/options.rs` | `--agent-context`, `--agent-session`, `--approval-timeout`, `--no-remote`. |
| `src/pam/remote_wake.rs` | Lets the hostd socket interrupt the password read while a request is pending. |

## Touched upstream files

| File | Change |
| --- | --- |
| `Cargo.toml` | `agent-approval` feature. |
| `src/sudo/mod.rs` | `mod agent` (feature-gated). |
| `src/pam/mod.rs` | `mod remote_wake` (feature-gated). |
| `src/pam/rpassword.rs` | One feature-gated block in `TimeoutRead::read_byte` before the upstream `poll`. |
| `src/common/error.rs` | `Error::Approval(String)` variant and its `Display` arm. |
| `src/sudo/cli/mod.rs` | Agent options in `TAKES_ARGUMENT` and the option match; parked via `set_options`. |
| `src/sudo/cli/tests.rs` | Parser tests for the agent options. |
| `src/sudo/pipeline.rs` | `auth_and_update_record_file`: upstream authentication wrapped in a closure; with the feature, `agent::authenticate` decides whether to create the session record. `set_mode` in `run` and `run_validate`. |
| `src/sudo/pipeline/edit.rs`, `list.rs` | `set_mode` one-liners. |
| `src/system/audit.rs` | `get_peer_credentials` also compiled (and `pub(crate)`) for `agent-approval`. |

## Behavioural contract

- The broker is consulted only when sudoers says *allowed, authentication required*
  and no valid session record exists. Denials and NOPASSWD never reach it.
- A remote approval skips `pam_authenticate` but still runs account management and
  session setup exactly as upstream.
- A remote approval does not create a session record unless the approver chose
  "refresh sudo timestamp" (`refresh=1`).
- `-n` asks hostd without blocking; only existing grants and delegations can approve.
- With a terminal (or `-S`/`-A`) the password prompt stays live. Ctrl-D, a prompt
  timeout, or exhausted attempts switch to waiting for the remote decision.
- Agent-supplied text is never read from files as root (there is no
  `--agent-context-file`); it is capped at 4000 bytes and marked untrusted by hostd.
