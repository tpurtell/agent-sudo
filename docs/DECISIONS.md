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
