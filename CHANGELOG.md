# Changelog

## 0.2.0 (2026-09-28)

Delegation you can say yes to without thinking about it.

- The approve sheet has one **Remember** card: just once, exactly this command,
  **this kind of work**, or anything this agent does. The model's suggestion is
  pre-selected and its scope is written under each choice.
- The model drafts the kind of work (`set-gpu-power: adjusting GPU power limits`)
  from the command. The agent's own note is never used. Drafts are linted and fall
  back to a template.
- Delegations have a deterministic **command filter** (a program with any arguments,
  the same leading arguments, or exactly these), checked before the model is asked.
- Fit is judged as "the same kind of work", ignoring values, and kept separate from
  the command's risk. Restoring a default after setting 300 W now fits.
- Every matching delegation is checked in one model call, narrowest first.
- Approving something a delegation handed over **widens** that rule instead of
  creating another; paused rules can be resumed and widened in one step.
- Delegations last an hour, a day, a month, or forever. A daily budget
  (`max_decisions_per_day`, default 50) replaces the 100-approval lifetime cap.
- A passkey is needed only for broad rules (no filter, all hosts, longer than a day,
  raised risk ceiling). On Edge and Chrome the notification updates with
  **Approve & remember** once the model has answered.
- "Group" means one named group, the host's smallest by default, never every group.
- Grants for any arguments are labelled that way.
- `agent-sudo -n` no longer says "request expired without a decision" when no grant
  or delegation matches.
- `advisor-test --delegation "intent"` checks fit against your own rules.

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
