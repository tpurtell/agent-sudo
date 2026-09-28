# agent-sudo: brokered privilege escalation for agent-driven machines

Status: draft v0.1 (2026-09-28). This is the implementation proposal handed to the
implementing model. It states intent, invariants, and the shape of each component.
It deliberately leaves internal details open. The implementer is expected to make
design corrections as requirements clarify, and to record each correction in
`docs/DECISIONS.md` so the proposal and the code do not drift silently.

Origin: `inspiring-discussion.md` in the repo root. Read it once for motivation;
this document supersedes it wherever they disagree.

## 1. What this is

`agent-sudo` is a drop-in `sudo` for environments where coding agents run on many
machines. When an agent runs `sudo`, the request goes to a central approval service
and shows up as a push notification on the operator's phone or desktop. The operator
approves once, optionally with a scope ("this exact command on the whole cluster for
30 minutes"), and the command runs. A human at a real terminal can still just type
their password; both paths race and the first success wins.

Three parts:

| Component | Runs as | Language | Role |
| --- | --- | --- | --- |
| `agent-sudo` binary | setuid root, per host | Rust, fork of sudo-rs | Same policy and execution semantics as sudo-rs, plus one new authentication outcome: *remotely approved*. |
| `agent-sudo-hostd` | root systemd service, per host | Rust | Holds the host identity, talks HTTPS to the service, relays approval requests from the setuid binary over a local socket. |
| approval service | Docker container, one per fleet | Rust (axum) + web UI | Users, passkeys, devices, push, requests, grants, deterministic policy, optional LLM advisor, audit. |

Plus two small deliverables: a PATH shim installer so agents transparently pick up
`agent-sudo` as `sudo`, and an optional agent skill that teaches agents to pass
`--agent-context "why"`.

## 2. Goals and non-goals

Goals

- Zero agent cooperation required. `sudo apt install foo` from an agent just works
  through the broker via the PATH shim. Context flags are optional polish.
- Local `/etc/sudoers` remains the hard ceiling. The service can never grant what
  sudoers denies. A compromised service cannot escalate an unprivileged account.
- One-tap approval from a phone most of the time. Passkeys for login; long-lived
  revocable sessions; step-up authentication only for dangerous classes.
- Every privileged decision is attributable: who, from which device, for which
  exact command, under which scope, and whether an LLM suggestion was followed.
- The forked binary stays auditable: compiled without the `agent-approval` feature it
  must be byte-for-byte upstream sudo-rs behavior, and the patch set stays small.

Non-goals (v1)

- Replacing the system `sudo` for humans. Install alongside; reach it via shim.
- Session recording, output capture, or command sandboxing.
- Fleet-wide sudoers distribution. Sudoers stays local and boring.
- LLM auto-approval. The mechanism is designed in and shipped disabled.
- Windows, macOS, or BSD hosts. Linux with PAM only.

## 3. Topology

```
 agent host (each Spark, workstation, worker)          approval service (Docker, TLS)
 ───────────────────────────────────────────           ────────────────────────────────
 agent ──exec──> ~/.agent-tools/sudo ─┐
                 (symlink)            │
                                      v
                 /usr/local/bin/agent-sudo  (setuid root, sudo-rs fork)
                     │  1. parse CLI, resolve command, evaluate /etc/sudoers
                     │  2. NOPASSWD or fresh timestamp? -> run, never contact service
                     │  3. else: open /run/agent-sudo/hostd.sock
                     v
                 agent-sudo-hostd (root)  ──HTTPS, signed requests──>  POST /api/v1/requests
                     │  builds the request envelope from                    │
                     │  facts it verifies itself via /proc                  ├─ policy engine: existing grant? class? step-up?
                     │  long-polls for the decision                         ├─ advisor (async): risk + suggested scope
                     v                                                      ├─ push to registered devices
                 decision {approved|denied|timeout}                        └─ live update to open UIs
                     │                                                      ^
                     v                                                      │ passkey-authenticated approver
                 agent-sudo executes (or fails) exactly like sudo-rs        phone PWA / desktop browser
```

The binary also keeps the normal PAM password path alive when a TTY is present, so a
human typing their password or a remote approval, whichever lands first, wins.

## 4. Security invariants

These are the rules the implementation must not violate. Tests should encode them.

1. **Sudoers is the ceiling.** The service is consulted only after sudoers has already
   said "allowed, but authentication required". A service response can replace
   *authentication*, never *authorization*. There is no "allow beyond sudoers" option.
2. **The setuid binary is the only thing that executes.** It resolves the executable
   and argv itself, before anything is sent to the service. The service sees the
   already-resolved command. Nothing returned by the service is executed or
   interpolated into the command. A grant is a yes/no plus an id.
3. **Policy-relevant facts come from root, never from the requester.** uid, gid,
   resolved executable path, argv, cwd, target user/group, tty presence, hostname,
   and the session fingerprint are established by the setuid binary or by hostd
   reading `/proc`. `--agent-context`, `--agent-session`, and environment values are
   *display-only* and are tagged `trusted: false` end to end (UI and advisor).
4. **The hostd socket is root-only.** `/run/agent-sudo/` is root-owned 0700. The binary
   verifies the peer is uid 0 via `SO_PEERCRED` before trusting a response. hostd
   verifies the connecting peer is uid 0 (the setuid binary) before serving it.
5. **Host identity never leaves the host.** hostd holds an Ed25519 key in a root-only
   file. Every request to the service is signed (body hash + timestamp + host id,
   short replay window). Enrollment is a one-time token minted in the UI by an admin.
   Revoking a host in the UI immediately stops its requests being accepted.
6. **Remote approval does not refresh the local sudo timestamp** unless the approver
   explicitly chose "authenticate normal sudo for N minutes". Otherwise a narrowly
   scoped remote approval would silently unlock unrelated `sudo` calls.
7. **The advisor cannot approve.** The advisor module has no code path that creates a
   grant or resolves a request. Its output is clamped by deterministic config before
   reaching the UI. Auto-approval, if ever enabled, is a deterministic rule that reads
   advisor output; the rule and its inputs are logged.
8. **Approval is a POST with CSRF binding and version check.** Opening a notification
   URL never approves. A decision on an already-resolved request returns 409.
9. **Fail closed for headless callers.** If hostd or the service is unreachable and
   there is no TTY, the request fails with a clear message. With a TTY, the normal
   password prompt still works and a one-line warning is printed.
10. **Secrets are scrubbed before the advisor.** A sanitizer redacts token-like argv
    values and environment before anything is sent to an LLM. The UI shows the
    unredacted command to the approver; the model never sees it.
11. **Everything is logged.** Requests, decisions (with approver, device, auth
    strength, scope, advisor suggestion and whether it was accepted), grant uses,
    enrollments, revocations, and admin changes go to an append-only audit table.

## 5. `agent-sudo` (the sudo-rs fork)

Base: sudo-rs `v0.2.15` (Apache-2.0 OR MIT), vendored as a git subtree at `sudo/`.
All fork changes are behind a Cargo feature `agent-approval`. `sudo/AGENT_SUDO_PATCH.md`
lists every touched file and why, to make rebasing onto upstream releases mechanical.

Dependency rule for the setuid binary: no new crates beyond what upstream uses (`libc`,
`glob`). The local socket protocol is therefore trivial by design (see §6). This is
the reason hostd exists rather than putting an HTTPS client in a setuid binary.

Behavior, in the order sudo-rs already does things (`src/sudo/pipeline.rs`):

1. Parse CLI. New long options, all optional, rejected if the feature is off:
   - `--agent-context TEXT` and `--agent-context-file PATH`: human explanation.
   - `--agent-session ID`: caller-claimed session label (untrusted, display/grouping).
   - `--approval-timeout DURATION`: cap on how long to wait for the remote decision.
   - `--no-remote`: skip the broker; behave exactly as upstream sudo-rs.
   Env fallbacks `SUDO_AGENT_CONTEXT`, `SUDO_AGENT_SESSION` for callers that cannot
   change argv. These are stripped from the target environment.
2. Resolve command and evaluate sudoers exactly as upstream. Denied means denied.
3. If sudoers says no authentication is needed, or the session record is fresh: run.
   The service is never contacted. This keeps "if sudo wouldn't ask, don't ask" true.
4. Otherwise, authentication is required. Connect to hostd. If the socket is absent or
   hostd refuses: TTY present means print one warning line and fall back to upstream
   PAM behavior; no TTY means fail with `agent-sudo: approval service unavailable`.
5. Send the request (§6) and then:
   - **TTY present**: show the normal `[sudo] password for tj:` prompt. The hidden
     input reader already polls a single fd with a timeout (`src/pam/rpassword.rs`);
     add the hostd socket fd to that poll set. Password entered: continue upstream
     PAM flow, which on success writes the session record as usual. Approval arrives:
     abort the PAM conversation, print `Approved remotely by <user> (<device>).`, and
     treat authentication as satisfied. Remote deny: print it and keep the prompt
     open unless the decision says `hard_deny`, in which case exit with an error.
   - **No TTY** (the common agent case, and `-n`): print `Waiting for approval
     (<request id>)…` to stderr and block on the socket until decision or timeout.
   - Cancellation: SIGINT or hangup during the wait sends a cancel to hostd so the UI
     marks the request as withdrawn.
6. On remote approval: run `pam_acct_mgmt` and `pam_open_session` as upstream does
   (they still apply), skip `pam_authenticate`, and do **not** create a session record
   unless the decision carries `refresh_local_timestamp`. Then exec exactly as upstream.
7. Log to syslog like upstream, with an added `APPROVAL=remote:<request id>` field.

Nothing else in sudo-rs changes: `sudoedit`, `-u`, `-g`, `-i`, `-s`, `-l`, `-v`,
environment handling, PTY handling, signals, and AppArmor are untouched.

Waiting defaults: 10 minutes total for a headless request, configurable in
`/etc/agent-sudo/client.conf` (root-owned, tiny key=value file: socket path, default
timeout, warn-or-fail when hostd is down for TTY sessions). The `--approval-timeout`
flag can only shorten it.

## 6. `agent-sudo-hostd`

A small root daemon. Responsibilities:

- **Serve the local socket** `/run/agent-sudo/hostd.sock`. Protocol is one request,
  one streamed response per connection. Request: newline-terminated `key=value`
  lines with percent-encoded values (so the setuid binary needs no JSON library),
  ending with an empty line. Response: `status` lines as state changes
  (`pending <request id>`, `approved <by> <device> [refresh-timestamp]`,
  `denied <reason> [hard]`, `timeout`, `error <message>`). hostd verifies the peer
  is uid 0 before reading anything.
- **Enrich the request with verified facts.** From the peer pid (`SO_PEERCRED`) and
  `/proc`: the requesting uid/gid and the full process ancestry. Derive a **session
  fingerprint**: the nearest ancestor whose executable name matches a configured agent
  list (`claude`, `codex`, `opencode`, `node` with a known script, …) or else the
  session leader, encoded as `pid:starttime:exe`. This is what "approve for this
  agent session" binds to. It is verified by root, not claimed by the agent; note that
  it does not separate two agents running as the same uid on the same host, which is
  not a boundary this system claims to enforce.
- **Sign and forward** to the service: `POST /api/v1/requests`, then long-poll
  `GET /api/v1/requests/{id}/decision?wait=25s` until resolved or the client's timeout
  passes; forward cancels. Retries with backoff on transient errors; never resubmits a
  request under a new id after the service has acknowledged it.
- **Enrollment**: `agent-sudo-hostd enroll --service URL --token ONE-TIME-TOKEN`
  generates the key, registers `(hostname, public key)`, stores the host id. Config in
  `/etc/agent-sudo/hostd.toml`: service URL, optional CA pin, agent executable list,
  history/telemetry knobs. Key in `/etc/agent-sudo/host.key` (0600 root).
- Reports host groups only as the service assigns them; hosts do not self-declare
  groups.

The request envelope sent to the service (JSON, all strings UTF-8 with lossy
escaping for non-UTF-8 argv):

```
host_id, hostname, requesting user {uid, name, groups}, target {uid, gid, names},
executable (resolved absolute path), argv, cwd, tty (bool + name),
launch type (direct|shell|login|edit), session fingerprint, process chain (short),
env summary (only SSH_CONNECTION presence, TERM, and whether -E was requested),
untrusted { agent_context, agent_session, tags }, client timeout, submitted_at.
```

## 7. Approval service

One container. Rust with axum, SQLite (single file, WAL), a static web UI. No Redis,
no Postgres, no background workers beyond tokio tasks. The container speaks plain HTTP
on one port and trusts `X-Forwarded-*` only from configured proxy addresses. Passkeys
and Web Push need a stable hostname with a publicly-trusted certificate, but the
service itself does not need to be reachable from the Internet. Two supported
front doors, both in `deploy/`:

- **Tailscale sidecar** (recommended for home labs): a `tailscale/tailscale`
  container with `tailscale serve` terminating HTTPS on `https://<name>.<tailnet>.ts.net`
  using Tailscale's automatic Let's Encrypt certificates and MagicDNS. Only tailnet
  devices can reach it, which is the right default for something that grants root.
  The service's configured origin and WebAuthn RP ID are that ts.net name.
- **Bring your own proxy**: any nginx/Caddy/Traefik with a real certificate, for
  operators who already run one.

### 7.1 Data model

`users` (id, name, password hash, role admin|approver), `passkeys`, `devices`
(user, label, kind, push subscription, last seen), `web_sessions` (opaque token hash,
device, created/last used/strong_auth_at/expires/revoked), `hosts` (id, name, public
key, groups, enrolled by, revoked), `enrollment_tokens`, `requests` (envelope, state,
version, timestamps, advisor result), `decisions`, `grants` (matcher, scope, ttl,
created by decision, uses, revoked), `audit` (append-only), `policy_classes` if
classes are stored rather than configured, and `settings`.

### 7.2 Request lifecycle

```
submitted ─┬─ matched existing grant ──────────────> approved (grant use recorded)
           ├─ auto-approve rule (off by default) ──> approved
           └─ pending ──> notify devices, advisor runs async, UI updates live
                  ├─ approver decision ──> approved | denied (hard or soft)
                  ├─ client cancel ──────> withdrawn
                  └─ client timeout ─────> expired
```

A grant is created only from an explicit approver choice of scope. Scope dimensions:

- command: `exact` (executable + argv) | `executable` (any argv) | `argv_prefix`
- hosts: `this host` | `host group(s)` | `all hosts`
- requester: `this unix user` | `this session fingerprint`
- ttl: bounded by class `max_ttl`
- `refresh_local_timestamp`: explicit, separate checkbox, off by default

Matching is deterministic and exact; no globbing in v1. Grant use is logged.

### 7.3 Policy engine (deterministic)

Config file (YAML or TOML, mounted read-only; hot-reloaded) with:

- `classes`: named matchers on executable and argv prefix (and optionally hosts/users)
  with `default_scope`, `max_ttl`, `require_each_time`, `hard_deny_on_remote_deny`,
  `step_up: none|recent(5m)|now`. First matching class wins; an implicit default class
  applies otherwise. Ship with a sane starter set: package managers, `systemctl`,
  root shells (`bash`, `sh`, `su`, `-i`, `-s`) with `require_each_time` and step-up.
- `approvers`: which users are notified for requests from which hosts/users. Default:
  every user with the approver role.
- `advisor`: provider, model, history window, output clamp (max suggested scope/ttl).
- `auto_approve`: present in the schema, documented, `enabled: false` by default, with
  the threshold shape sketched in the origin discussion.

The policy engine also computes deterministic features attached to every request
(root-shell capable, package manager, service control, touches `/etc`, writes to
approval-system paths, matches a recent approved command) so the UI and advisor share
one vocabulary.

### 7.4 Web authentication and devices

- Login: username + password once, then register a passkey. Subsequent logins are
  passkey-only when one exists. Password reset is admin-driven.
- Sessions: opaque 256-bit token, `HttpOnly; Secure; SameSite=Strict`, server-side
  record, idle expiry 7 days, absolute 30 days, both configurable. Every session is a
  row tied to a device and revocable from the devices page.
- `strong_auth_at` is set on passkey use. Classes with `step_up` require it to be
  recent, or trigger a fresh passkey ceremony inline on the approval screen.
- Devices page: label, passkey status, push status, last active, revoke.
- Push: Web Push (VAPID) subscriptions per device; payload contains only the request
  id and a short title. The PWA (manifest + service worker) makes iOS notifications
  work once added to the home screen. Notification click opens `/requests/{id}`.
- All state-changing endpoints require the session cookie plus a CSRF token issued
  per session and sent as a header.

### 7.5 UI

Vanilla TypeScript, no framework required, built with Vite into static files served
by the service. Live updates over SSE or WebSocket. Phone-first layout. Pages:

- Pending requests (the landing page): card per request with host, user, command,
  cwd, agent context (visibly marked "agent-supplied"), risk summary once available,
  suggested scope pre-filled, Approve / Deny, and an expandable "why" with the
  deterministic features and history matches.
- Request detail and history with filters.
- Grants: active grants with matcher, scope, remaining ttl, uses; revoke.
- Hosts: enrolled hosts, groups, last seen, mint enrollment token, revoke.
- Devices and account; admin user management.
- Policy: read-only view of the loaded config and the class each request matched.

### 7.6 Advisor

Trait `DecisionAdvisor` with two backends behind one normalized result:

- `openai-compatible`: chat completions with a strict JSON schema response. Works
  with any gateway (the reference deployment points at a LiteLLM instance or
  OpenRouter directly).
- `openrouter-decisions`: `POST https://openrouter.ai/api/alpha/decisions` with one
  `score` question for overall risk and `noul` questions for destructive, privilege
  escape, persistence, credential access, and network/security change, plus a
  `choice` question for suggested scope. Probabilities are kept and displayed.

Inputs: the sanitized request, deterministic features, the matched class and its
envelope, and recent history (`max_requests`, `max_age`, same user, prefer same
session and same host group). The prompt states that argv, cwd, and agent context are
untrusted data, never instructions.

Normalized output: risk 0–100 with confidence, per-dimension probabilities, suggested
decision/scope/ttl, and a short summary. The clamp step enforces the class envelope
before storage. Advisor failure or slowness never blocks the request; the UI shows
"analysis unavailable". Advisor calls, latency, cost, and raw responses are logged.

### 7.7 HTTP API (shape only)

Host-facing, signature-authenticated: `POST /api/v1/requests`,
`GET /api/v1/requests/{id}/decision?wait=`, `POST /api/v1/requests/{id}/cancel`,
`POST /api/v1/enroll`.

Browser-facing, cookie-authenticated: auth and passkey ceremonies, `GET /api/requests`,
`POST /api/requests/{id}/decision` (decision, scope, request version), grants, hosts,
devices, push subscription, policy view, audit export (JSON lines), and an SSE stream.

## 8. Shim and skill

- `agent-sudo shim install [DIR]` (a subcommand of hostd's CLI, not of the setuid
  binary) creates `DIR/sudo` and `DIR/sudoedit` symlinks to the binary, defaulting to
  `~/.agent-tools`, and prints the `PATH` line to add to the agent's environment. It
  never touches `/usr/bin/sudo`.
- `skills/agent-sudo/SKILL.md`: a short skill for coding agents. When escalation is
  needed, use `sudo` as usual, add `--agent-context` with one sentence on why and what
  will change, do not split one logical operation into several requests, and expect
  `Waiting for approval` to take up to several minutes. Include a Claude Code
  compatible layout and a plain-markdown variant for other agents.

## 9. Repository layout and engineering rules

```
agent-sudo/
  README.md  LICENSE-APACHE  LICENSE-MIT  COPYRIGHT (sudo-rs notices retained)
  docs/PROPOSAL.md  docs/DECISIONS.md  docs/SECURITY.md  docs/PROTOCOL.md  docs/DEPLOY.md
  sudo/            # git subtree of sudo-rs v0.2.15 + feature-gated patch
  hostd/           # agent-sudo-hostd crate
  service/         # approval service crate; service/web/ is the UI
  protocol/        # shared serde types used by hostd and service (not by sudo/)
  skills/agent-sudo/SKILL.md
  deploy/          # generic docker-compose.yml, example nginx, example config, install.sh
  private/         # gitignored: operator-specific infrastructure
```

- Cargo workspace at the root; `sudo/` builds with `--features agent-approval`.
- License: match sudo-rs (Apache-2.0 OR MIT) for the whole repo unless decided otherwise.
- `cargo clippy -D warnings`, `cargo fmt`, and `cargo test` must pass in CI. The
  setuid binary keeps upstream's `unsafe` discipline and lint configuration.
- Tests: unit tests for the socket protocol codec, policy matching, grant matching,
  clamp, sanitizer, and signature verification; service integration tests with an
  in-memory SQLite; an end-to-end compose test with a privileged "host" container
  running the setuid binary and hostd against the service, driving approvals through
  the API. Upstream's `test-framework` stays runnable to prove no regressions when
  the feature is off.
- Every commit that changes an invariant in §4 updates `docs/SECURITY.md`.
- Commit early and often; small PR-sized commits with descriptive messages.

## 10. Deployment (generic)

`deploy/` ships a compose file with the service plus two profiles for the front door
(Tailscale sidecar, or an example nginx TLS proxy), an example `policy.yaml`, and
`install.sh` for hosts (installs the binary 4755 root, the hostd
unit, and runs enrollment). `docs/DEPLOY.md` walks through: run the service, create
the first admin, register a passkey, mint an enrollment token, enroll a host, install
the shim into an agent environment, run `sudo true` from the agent, approve on the
phone.

Operator-specific deployment lives outside this repo and is not referenced from it.

## 11. Milestones

1. **Skeleton and protocol.** Workspace, subtree import, protocol crate, hostd socket
   server with a fake "always approve after 2s" service stub, feature-gated fork that
   waits on the socket for headless callers. Demo: `sudo true` from a pipe is approved
   by the stub.
2. **Service core.** Requests, grants, deterministic policy, host enrollment and
   signatures, admin bootstrap, cookie sessions, minimal UI with approve/deny, SSE.
   Demo: approve from a browser.
3. **Passkeys, devices, push, PWA.** Demo: phone notification, one-tap approve.
4. **Interactive race.** TTY poll integration, remote-approve message, timestamp
   semantics, hard-deny classes, cancel on SIGINT. Demo: password and phone race.
5. **Advisor.** Both backends, sanitizer, clamp, history, UI "why" panel.
6. **Polish and ship.** Shim installer, skill, install script, docs, CI, e2e test,
   first tagged release.

## 12. Implementer latitude

Free to change: crate choices, the exact socket line format, SSE versus WebSocket,
SQLite schema details, the UI toolkit, the advisor prompt and question set, config
file format, and milestone ordering. Must not change without recording a decision:
anything in §4, the "sudoers is the ceiling" rule, the no-new-deps rule for the setuid
binary, and the "advisor cannot approve" boundary.
