# Decisions

Append-only log of design decisions. The implementer adds an entry whenever the code
departs from `PROPOSAL.md` or resolves something it left open.

## 2026-09-28 Initial decisions (operator)

- **Root hostd relay.** The setuid binary never speaks TLS or HTTP. A root systemd
  daemon holds the host identity and talks to the service; the binary talks to it over
  a root-only unix socket. Rationale: seven hosts share one network-hosted service, so
  network code must exist somewhere, and keeping it out of the setuid binary preserves
  sudo-rs's dependency discipline. Trusting hostd equals trusting root, so no extra
  grant-signature layer inside the binary.
- **Service stack.** Rust, axum, SQLite, vanilla TypeScript UI built with Vite.
- **Front door.** Tailscale sidecar (`tailscale serve`, MagicDNS, automatic certs) is
  the primary deployment. An nginx bring-your-own-cert profile is developed alongside
  it and is the profile automated tests use, with a harness-generated test CA.
- **No root on the development host.** All privileged steps run inside Docker.
  Real-environment installation on the operator's machines happens together after
  review.
- **License.** Apache-2.0 OR MIT for the whole repository, retaining sudo-rs notices.
- **Operator infrastructure stays out of the repo.** Hostnames, tailnet names, deploy
  scripts for the operator's NAS and hosts live in the gitignored `private/` folder.

## 2026-09-28 Delegated automation is a goal (operator)

- Risk scoring and suggested scope are the baseline advisor behavior and are on
  whenever an advisor is configured.
- Automated approval is a goal, not a deferred option, via human-created
  **delegations** with bounded scope, ttl, risk limits, forbidden features, drift
  guards, and a global kill switch (PROPOSAL §7.8). Zero delegations ship by default.
- The advisor still never holds authority of its own; the deterministic policy engine
  makes every automated decision by applying a delegation to a clamped assessment.
- Reference test model: an official DeepSeek route behind an OpenAI-compatible
  gateway; decision-model routing may later go through the same gateway.

## 2026-09-28 Implementation (first build)

Structure
- `sudo/` stays outside the Cargo workspace. It keeps upstream's lockfile, lints and
  release profile, so the fork builds and audits exactly like sudo-rs.
- The fork's changes live in new modules (`src/sudo/agent/`, `src/pam/remote_wake.rs`)
  plus about 100 lines in upstream files, all behind the `agent-approval` feature.
  The existing `get_peer_credentials` helper from sudo-rs is reused for SO_PEERCRED.
- The broker is enabled by the presence of `/etc/agent-sudo/client.conf` (root-owned,
  not group/world writable). Installing the binary alone changes nothing.

Behaviour the proposal left open or got wrong
- **No `--agent-context-file`.** A setuid root binary reading a caller-chosen path
  would let anyone send `/etc/shadow` to the approver. Use `--agent-context "$(cat f)"`.
- **`sudo -n` is a non-blocking check.** It asks hostd whether a grant or delegation
  covers the request and never creates a pending request (those are stored as quiet
  records, hidden from the UI by default). Blocking would have made scripts'
  `sudo -n true` probes spam approvers.
- **The terminal race** uses the hostd socket as a second fd in the password reader's
  poll. Ctrl-D, a prompt timeout, or exhausted attempts switch to waiting for the
  remote decision instead of failing. A soft remote denial re-opens the prompt.
- hostd checks that the request's pid equals SO_PEERCRED's and that the process's
  real uid matches the claimed uid.
- **Session fingerprints** are `boot-id:pid:starttime` of the nearest agent-looking
  ancestor (or the session leader). Multi-host grants and delegations therefore bind
  to the unix user: the UI switches "who" to the user when "where" widens, and the
  advisor clamp does the same.
- **Delegation limits were recalibrated** against DeepSeek V4 Flash: the proposal's
  implied tight ceilings rejected ordinary driver installs (persistence and privilege
  escape scores of 0.25–0.65 are normal for DKMS). Defaults are now configurable
  (`policy.automation.default_limits`) and relevance plus overall risk do most of the
  gating.
- **Deterministic risk floors** (root shell, credentials, destructive, changes to sudo,
  `sudo -v`) are applied after the model, and a new setuid/setcap feature treats
  `chmod 4755`/`u+s`/`setcap` as root shells.
- Model replies are parsed leniently (duplicate keys: last wins) and retried once.

Service and UI
- Web Push is implemented in-house (RFC 8291 aes128gcm + RFC 8292 VAPID with p256,
  hkdf and aes-gcm) rather than via a crate; passkeys use webauthn-rs, with a
  `residentKey: preferred` hint so passkey-only sign-in works without a username.
- Once a user has a passkey, password sign-in is refused (configurable). Recovery is
  a CLI-issued one-time invitation.
- SSE for browsers, long-poll for hosts, one SQLite connection behind a mutex.
- The first-run setup link comes from the log (or `AGENT_SUDO_SETUP_TOKEN`).
- The UI is dependency-free TypeScript built with Vite (about 30 KB gzipped).
  Notification Approve/Deny buttons work where the platform supports actions (Edge,
  Chrome); the service worker reads the CSRF token from IndexedDB.

Testing
- No root on the development machine: everything privileged runs in containers. The
  e2e runner is Playwright in Docker with the throwaway CA in Chromium's NSS store,
  using full Chromium (the headless shell has no notification support).
- OpenRouter's Decisions endpoint is `https://openrouter.ai/api/alpha/decisions`. The
  operator's OpenRouter guardrail currently blocks `typesafe/jev-1.13`, so that backend
  is covered by parser tests against the documented response, not a live call.

## 2026-09-28 Security review fixes

An independent review of the first build found these; all are fixed and tested
(service integration tests and the e2e suite).

- **Environment overrides were invisible.** sudo-rs `ALL` rules imply SETENV, so
  `sudo LD_PRELOAD=… cmd` or `--preserve-env` could change what a grant or approval
  ran. The binary now sends every override; the UI shows them in the command line;
  anything outside a short benign list (`DEBIAN_FRONTEND`, `LANG`, `TZ`, …) is a root
  shell; overrides are part of `command_key` and grant matching.
- **Naming bypasses of the "never automated" checks.** hostd now reports executable
  facts and resolved paths; classification uses the canonical executable name and
  every spelling of path arguments; requester-modifiable executables are root shells;
  chmod modes are parsed properly (`04755`, `a+rwx,u+s`).
- **Grants were bound to a path string.** Requests whose target could change after
  approval (requester-owned symlinks, unverified executables) are never grantable, and
  grants bind target group, launch type, chdir, and environment too.
- **Delegation limits raced the model call.** Uses are claimed with a conditional
  update after the model returns, and the kill switch is re-checked.
- **A losing decision left a grant behind.** Decision and grant/delegation creation
  are one transaction.
- **First passkey registration counted as step-up.** It no longer does.
- **Enrollment tokens were not consumed atomically.** They are now.
- Also: nonces are kept for twice the allowed skew, standalone delegations can't
  silently widen their requester scope, a missing model dimension fails its ceiling,
  push endpoints must be known push services, and hostd's unit no longer hides `/home`
  and `/tmp` (it needs them to judge executables and paths).

## 2026-09-28 Delegation you can almost always say yes to (0.2.0)

The first real use exposed the gap: a Codex agent alternated `set-gpu-power 300 300`
and `set-gpu-power` (restore 400 W). Ticking "delegate" copied the agent's note into
the intent, so the rule memorised "300 W", the restore was judged a different task,
and each approval stacked another delegation. The operator wants delegating to be
the default, broad but smart, with forever as an option.

- One human-facing concept on the sheet ("Remember"), two engines underneath: exact
  grants (no model) and delegations (judged). Grants and delegations stay separate
  tables.
- Delegations gain a deterministic command filter. The filter admits; the intent
  can only turn requests away. That is why a model-drafted intent is acceptable.
- The intent is drafted by the model as a *kind of work*, linted, and anchored to
  the program; the agent's text is never offered. `intent_source` records who wrote
  it.
- Risk and fit are separate questions in the prompt; fit ignores values.
- All matching delegations are evaluated in one call, narrowest first; only the
  narrowest rule's decline streak counts towards pausing it.
- Widening replaces duplicating. Widening only grows scope and expiry.
- Lengths: 1 hour, 1 day, 1 month, forever. A daily budget replaces the lifetime cap
  so forever rules don't exhaust themselves. `automation.max_ttl_minutes` defaults
  to 0 (no limit).
- Passkey only for rules broader than a passkey-free "any arguments" grant. This
  enables a one-tap "Approve & remember" notification action on browsers with
  notification buttons; the update push goes only to Chrome's and Windows' push
  services so Safari and Firefox don't buzz twice.
- Not done: dropping `sudo -n` rows (they are already hidden by default and the
  Activity page can show them), merging grants and delegations into one table, and
  a per-rule memo that skips the model for byte-identical repeats.

