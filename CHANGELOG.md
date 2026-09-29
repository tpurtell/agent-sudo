# Changelog

## 0.2.1 (2026-09-29)

A service release. Homebrew hosts keep the 0.2.0 bottles; the two installer fixes
reach hosts installed with `curl …/install.sh` now and Homebrew hosts with the next
bottles.

- Enrolling failed when the one-time token happened to start with `-` (about one
  in 64): the installer passed it so it read as an option. The installer now passes
  `--token=…`, and new tokens never start with `-`.
- Creating, widening or resuming a delegation or grant now re-checks the requests
  already waiting, so remembering one of a batch (the same command on six hosts)
  releases the rest instead of leaving each for a human. Their notifications are
  replaced quietly with the outcome.
- The advisor's secret filter now knows which arguments common programs take as
  passwords (`mysql -p…`, `sshpass -p`, `curl -u`, `htpasswd -b`, `openssl passwd`,
  `smbclient -U user%…`, `nmcli`, LDAP, Redis, IPMI and more), hides what is echoed
  into `chpasswd`, `sudo -S`, `--password-stdin` or `cryptsetup`, reads inside
  `bash -c` strings and history, and also filters the `--chdir` directory and the
  session names. Before, short passwords given as plain arguments reached the model.
- `agent-sudo-setup` no longer prints the first-install enroll hint when upgrading,
  and waits for the relay's socket before reporting its status.

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
