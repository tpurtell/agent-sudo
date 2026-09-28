# Changelog

## 0.1.0 (2026-09-28)

First release.

- `agent-sudo`: a feature-gated sudo-rs fork that asks an approval service once
  sudoers requires authentication, racing the password prompt when there is a terminal.
- `agent-sudo-hostd`: root relay with signed requests, `/proc` session facts,
  executable and path facts, the PATH shim and the agent skill installer.
- `agent-sudo-service`: approval service with passkeys, web push, grants, an optional
  decision model, delegations, an audit log, and `init` for deployments.
- Installs from Homebrew (`tpurtell/local-ai/agent-sudo` plus `agent-sudo-setup`) or
  from the service's `/install.sh`.
