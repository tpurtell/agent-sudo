---
name: agent-sudo
description: Use when a task needs root or sudo on a machine that uses agent-sudo (sudo requests are approved remotely by a human). Explains how to run privileged commands so the approver can decide quickly.
---

# Running privileged commands with agent-sudo

On this machine `sudo` is brokered: each privileged command is sent to a human
approver's phone or desktop, possibly with an AI risk assessment, and runs once they
approve. You don't need a password. Keep using `sudo` normally, with these habits.

## Explain why, in one sentence

Add `--agent-context` before the command. The approver sees it next to the exact
command line:

```sh
sudo --agent-context "Installing kernel headers needed to build the NVIDIA RDMA module" \
  apt-get install -y linux-headers-$(uname -r)
```

Say what the command is for and what will change. Plain words, no markdown, under
about 200 characters. The approver is told this text is unverified, so it must be
accurate: a misleading explanation gets denied and makes later approvals slower.

If you can't change the command line (a script calls sudo for you), set the
environment variable instead: `SUDO_AGENT_CONTEXT="…" ./install.sh`.

## Expect to wait

`sudo` prints `waiting for approval [CODE] https://…` and blocks until a human
decides, up to about 10 minutes. That is normal. Don't retry, don't background it,
and don't switch to a workaround while it waits. Tell the user you are waiting for
sudo approval and mention the code so they can match it on their phone.

- `approved by …`: the command ran.
- `denied by …: reason`: respect it. Read the reason, change the plan, and ask the user
  if you're unsure. Don't resubmit the same command.
- `timed out` or `expired`: ask the user whether to try again.

## Keep requests reviewable

- One logical operation per sudo call. Don't split an install into many tiny calls,
  and don't bundle unrelated work into `sudo bash -c "…"`.
- Prefer specific commands over shells. `sudo bash`, `sudo -i`, `sudo su`, and
  interpreters like `sudo python3` are root shells: they always need a fresh human
  decision and can never be pre-approved.
- Don't use `sudo -S`, askpass, or anything that tries to supply a password.
- `sudo -n` never waits: it succeeds only if the user already granted a standing
  approval. Use it to check, not to work around the approval.
- Never try to modify sudoers, PAM, `/etc/agent-sudo`, or the agent-sudo binaries.
  Those requests always go to a human with extra verification.
