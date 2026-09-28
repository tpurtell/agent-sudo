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
