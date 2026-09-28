# Security model

agent-sudo lets coding agents run privileged commands with a human in the loop. It is
security software; this document states what it protects, what it assumes, and the
invariants the code must keep. Changes to an invariant must update this file.

## Trust boundaries

```
agent (untrusted) ──exec──> agent-sudo (setuid root, sudo-rs fork)
                                │  root-only unix socket, SO_PEERCRED both ways
                                v
                          agent-sudo-hostd (root)  ──HTTPS + Ed25519 signatures──> service
                                                                                     │
                                                         approver browser (passkey, cookie + CSRF)
```

| Component | Trusted for | Not trusted for |
| --- | --- | --- |
| Agent / requesting user | nothing | its explanation text is display-only |
| `agent-sudo` (setuid) | resolving the command, enforcing sudoers, executing | — |
| `agent-sudo-hostd` (root) | session facts from `/proc`, holding the host key | deciding anything |
| Service | recording decisions, grants, delegations | widening what sudoers allows |
| Decision model | nothing; its output is advice | approving on its own authority |
| Approver's browser | decisions, within its role and freshness of passkey use | — |

## Invariants

1. **sudoers is the ceiling.** The service is consulted only after sudoers says
   *allowed, authentication required*. A remote decision replaces authentication,
   never authorization. Denied or NOPASSWD commands never reach the service.
2. **Only the setuid binary executes**, using the command it resolved itself before
   asking. Nothing from the service is executed or interpolated.
3. **Decision inputs come from root.** uid, target, resolved executable, argv,
   environment overrides, cwd, tty, and the session fingerprint are established by the
   binary or by hostd from `/proc`. hostd also `stat`s the executable (canonical path,
   owner, whether the requester could modify or replace it) and resolves path-like
   arguments against the working directory. Environment overrides other than a short
   benign list, executables the requester can modify, and setuid/setcap changes are
   classified as root shells. Requests whose target could change after approval (a
   path through a requester-owned symlink, an executable hostd could not verify, or
   non-UTF-8 arguments) can be approved once but never become grants or delegations.
   Grants bind the executable, arguments, target user and group, launch type, working
   directory, and environment.
   `--agent-context`, `--agent-session` and environment values are labelled untrusted
   in the UI and in the model prompt. The binary never reads files for agent text
   (there is no `--agent-context-file`; root could be tricked into reading
   `/etc/shadow`).
4. **The socket is root-only.** `/run/agent-sudo` is 0700 root. The binary refuses a
   peer that is not uid 0; hostd refuses peers not in `allow_peer_uids` (root only in
   production) and checks that the claimed pid and uid match the kernel's.
5. **Host identity never leaves the host.** Each host signs every request with its
   Ed25519 key (method, path, host id, timestamp, nonce, body hash). The service
   rejects skew over 120 s, replayed nonces, and revoked hosts. Enrollment tokens are
   single use and expire.
6. **A remote approval does not refresh the sudo timestamp** unless the approver
   explicitly chooses "also unlock ordinary sudo", which requires a recent passkey.
7. **The model never holds authority.** The advisor returns assessments. Automated
   approvals happen only when a human-created delegation matches and deterministic
   limits pass: scope, command filter, time, daily budget, risk ceiling,
   per-dimension ceilings, fit with the stated kind of work, and features that are
   never automated (root shells, credentials, changes to sudo/PAM/agent-sudo,
   `sudo -v`, non-UTF-8 arguments). A deterministic risk floor stops a model from
   calling a root shell routine. Model errors and timeouts fall back to a human. A
   kill switch, flagging, and drift guards pause automation.
   The model also drafts the kind of work a new delegation covers. That draft can
   only narrow what a delegation approves (fit can only turn a request away); what a
   delegation admits is set by its deterministic filter and scope, chosen by the
   approver's tap. Drafts are linted (no values, paths, widening words, or text
   echoed from the requester) and anchored to the program name, and the requester's
   own explanation is never offered as an intent.
8. **Browser actions are CSRF-safe and versioned.** Opaque server-side session tokens in
   `__Host-` cookies (`HttpOnly; Secure; SameSite=Strict`), a per-session CSRF header,
   and an Origin check on every state change. Decisions carry the request version;
   stale or duplicate decisions get 409, and the state change and any new grant or
   delegation commit in one transaction. Grant and delegation uses are claimed with a
   single conditional update, and a delegation is re-checked after the model returns.
   Enrollment tokens are consumed atomically. Opening a notification never approves.
   Registering a passkey does not count as step-up; push subscriptions must point at
   a known browser push service.
9. **Fail closed without a terminal.** If hostd or the service is unreachable, a
   headless request fails. With a terminal, the normal password prompt remains
   (configurable to deny).
10. **Secrets are redacted before the model.** Token-like values, credentials in URLs,
    key=value secrets, values after secret-bearing flags, and private keys are
    removed from everything sent to the advisor. The approver sees the real command.
11. **Everything is audited** in an append-only table: submissions, decisions (with
    device, auth freshness, scope, and whether the suggestion was followed), grant and
    delegation lifecycle, automated verdicts with their reasons, enrollments, sign-ins
    and failures, and administrative changes.

## Step-up authentication

| Action | Requirement |
| --- | --- |
| Approve an ordinary request | a signed-in approver session |
| Approve a class with `step_up = recent` (root shells, credentials) | passkey within `strong_auth_minutes` |
| Approve a class with `step_up = always` (changes to sudo itself) | passkey within the last minute |
| Create or widen a delegation with a program filter, for one host or group, up to a day | a signed-in approver session |
| Refresh the sudo timestamp; create or widen a delegation with no filter, for anyone, for all hosts, for longer than a day, or with a raised risk ceiling; resume a paused one | passkey within `strong_auth_minutes` |
| Turn automation on (turning it off needs nothing) | admin + recent passkey |
| Enroll or revoke hosts, invite or change users, remove a passkey | admin (where relevant) + recent passkey |

Once a user has a passkey, password sign-in is refused unless
`sessions.password_after_passkey = true`. Recovery uses `agent-sudo-service reset-user`
on the server, which prints a one-time invitation link.

## Known limits

- Paths are resolved when the request is made. A requester who controls a directory
  on the path (rather than a symlink) can still swap files between approval and
  execution; approve writes into user-owned locations with that in mind.
- In a terminal, a remote approval interrupts an in-progress PAM conversation, which
  PAM records as one failed attempt. With `pam_faillock` configured aggressively this
  counts toward lockout.
- Classification by name cannot recognise every program that runs arbitrary code;
  the model assessment and your own classes cover the rest.

- The session fingerprint separates agent sessions, not users. Two agents running as
  the same uid on one host can use each other's session-scoped grants.
- Anyone with root on a host can impersonate that host to the service within what
  that host's sudoers allows: root on a host already has root there.
- A compromised service can approve requests that local sudoers permits, but cannot
  widen sudoers. Keep sudoers as narrow as your workflow allows.
- Model assessments are advisory and can be wrong or manipulated by crafted
  arguments. They are clamped and never decisive on their own.
- Web Push payloads pass through the browser vendor's push service (encrypted
  end to end with the subscription keys); they contain the command line and the
  agent's explanation.

## Reporting

Please report vulnerabilities privately through GitHub security advisories on the
repository rather than public issues.
