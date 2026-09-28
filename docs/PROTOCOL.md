# Protocols

## Binary ↔ hostd (unix socket)

The setuid binary may not take dependencies, so this is a line protocol. Values are
percent-encoded: bytes outside `A-Za-z0-9-._~/:@,+` become `%XX`. Both ends share
test vectors (`sudo/src/sudo/agent/wire.rs`, `protocol/src/wire.rs`).

Request, one per connection, ended by an empty line:

```
agent-sudo-request v=1
mode=run                 run | edit | list | validate
nonblocking=0            1 for sudo -n: answer immediately, never create a pending request
interactive=1            1 if a password prompt is possible (tty, -S or -A)
pid=4242                 must equal the kernel's SO_PEERCRED pid
hostname=moa
user=tj
uid=1000
gid=1000
target_user=root
target_uid=0
target_group=root
target_gid=0
timeout_secs=600
launch=direct            direct | shell (-s) | login (-i)
command=/usr/bin/apt     resolved absolute path
arg=install              repeated, in order
arg=-y
env=DEBIAN_FRONTEND=noninteractive   repeated: VAR=value and --preserve-env overrides
cwd=/home/tj/project
tty=/dev/pts/3
context=Installing%20headers   untrusted
session=build-7                untrusted
```

Replies, one per line, `verb key=value…`:

| Line | Meaning |
| --- | --- |
| `pending id= code= url=` | waiting for a human; `code` is shown in the terminal and the UI |
| `approved id= by= via=user\|grant\|delegation label= refresh=0\|1` | final; `refresh=1` means create the sudo timestamp |
| `denied id= by= via= reason= hard=0\|1` | final; `hard=1` also blocks the password path |
| `expired id=` | final; nobody decided in time |
| `unavailable reason=` / `error message=` | the service could not be reached or the request was invalid |

The binary may send `cancel reason=password|timeout|error` before closing; hostd also
treats a closed connection as a cancel.

## hostd ↔ service (HTTPS)

JSON bodies are defined in `protocol/src/api.rs`. The request envelope adds facts hostd
gathers as root: `executable` (canonical path, owner, mode, whether the requester can
modify it) and `paths` (each path-like argument resolved against the working directory,
flagging requester-owned symlinks). Every request except enrollment carries:

```
x-agent-sudo-host:      <host id>
x-agent-sudo-time:      <unix seconds>
x-agent-sudo-nonce:     <32 hex chars, unique per request>
x-agent-sudo-signature: base64(Ed25519(canonical))

canonical = "agent-sudo-v1\n" METHOD "\n" path?query "\n" host_id "\n" time "\n" nonce "\n" hex(sha256(body))
```

| Endpoint | Purpose |
| --- | --- |
| `POST /api/v1/enroll` | `{token, hostname, public_key, hostd_version}` → `{host_id, name}`; unsigned, token is single use |
| `POST /api/v1/requests` | submit a `RequestEnvelope`; idempotent on `client_request_id`; may return a final decision immediately (grant, delegation, policy, `sudo -n`) |
| `GET /api/v1/requests/{id}/decision?wait=25` | long-poll until final or timeout |
| `POST /api/v1/requests/{id}/cancel` | `{reason}` |
| `POST /api/v1/heartbeat` | liveness, returns the host's groups |

## Browser ↔ service

Cookie-authenticated JSON under `/api/`, with `x-csrf-token` on every state change.
Live updates are Server-Sent Events on `/api/events` (`request`, `grants`, `hosts`,
`devices`, `settings`, `users`), each telling the client what to refetch.

Web Push payloads (encrypted per RFC 8291, VAPID per RFC 8292):

```json
{"t": "request", "id": "req_…", "v": 1, "code": "K7QX", "title": "claude on moa wants sudo",
 "body": "apt install -y jq\nInstalling jq…", "quick": true, "danger": false, "url": "/r/req_…"}
{"t": "auto", "id": "req_…", "delegation": "dlg_…", "title": "Approved automatically on emu", "body": "…"}
{"t": "digest", "delegation": "dlg_…", "title": "3 automated approvals", "body": "…"}
```

`quick` requests get Approve/Deny notification buttons where the platform supports
them (Edge, Chrome). The service worker posts the decision with the session's CSRF
token; anything needing a passkey opens the app instead.
