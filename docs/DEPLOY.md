# Deploying agent-sudo

Three pieces: the **approval service** (one per fleet, in Docker), **hostd** plus the
**agent-sudo** binary on each host, and your **devices** (any modern browser).

## 1. The approval service

Passkeys and Web Push need a stable HTTPS origin with a publicly trusted certificate.
The service does not need to be reachable from the Internet. Pick a front door:

### Tailscale (recommended)

The sidecar joins your tailnet and serves `https://<TS_HOSTNAME>.<tailnet>.ts.net`
with an automatic Let's Encrypt certificate. Only tailnet devices can reach it.

1. In the Tailscale admin console enable **MagicDNS** and **HTTPS certificates**.
2. Declare a tag for the service in your tailnet policy file, so the device belongs to
   the tag rather than a person and never expires:

   ```json
   "tagOwners": { "tag:agent-sudo": ["autogroup:admin"] }
   ```

3. Create an auth key under Settings → Keys → **Generate auth key**: not reusable, not
   ephemeral, pre-approved, with the tag `tag:agent-sudo`. The key is only used for the
   first start, so its expiry doesn't matter afterwards.
4. Choose the hostname (`TS_HOSTNAME`) now. It becomes part of the service's address,
   and passkeys are tied to that address for good.
5. Configure and start:

   ```sh
   cd deploy/service
   cp .env.example .env                    # TS_AUTHKEY, TS_HOSTNAME, public URL, model
   cp service.example.toml service.toml
   docker compose --profile tailscale up -d
   ```

6. Open the setup link from the service log: `docker compose logs service | grep setup`.

The device's identity is kept in the `tailscale` volume, so restarts and upgrades don't
need the key again; you can remove it from `.env` once the device appears. Back that
volume up with `data`, and never commit it anywhere.

**Without an auth key.** Leave `TS_AUTHKEY` empty and the sidecar prints a login link
(`docker compose logs tailscale | grep login.tailscale.com`). Approve it, then choose
**Disable key expiry** for the device under Machines, or it is logged out after about
180 days.

### Your own certificate (nginx)

Put `fullchain.pem` and `privkey.pem` where `TLS_CERT`/`TLS_KEY` point and run
`docker compose --profile nginx up -d`. Set `public_url` to the exact
`https://host:port` browsers will use.

### Configuration notes

- `public_url` is baked into every passkey. Changing it later means re-registering
  passkeys, so choose the final name first.
- Back up the `data` volume (SQLite). It holds users, passkeys, hosts, grants, and the
  audit log. The VAPID push key lives there too; losing it means devices must
  re-enable notifications.
- Lost your only passkey? On the server:
  `docker compose exec service agent-sudo-service reset-user <name> --remove-passkeys`
  prints a one-time link to set a new password and register a new passkey.
- `agent-sudo-service advisor-test "/usr/bin/apt install -y jq"` runs the configured
  model against a sample request and prints its assessment.

## 2. Hosts

Build the host binaries for the host's architecture (Debian bookworm glibc, so they
run on Ubuntu 22.04 and later):

```sh
docker build --target host-dist --output dist .                          # this machine's arch
docker buildx build --platform linux/arm64 --target host-dist --output dist-arm64 .
```

Cross-architecture builds need QEMU binfmt or a native builder (for example a buildx
builder on an arm64 machine).

On each host, as root:

```sh
./install.sh --enroll https://agent-sudo.example.ts.net <token-from-the-UI>
```

This installs `/usr/local/bin/agent-sudo` (setuid root), `/usr/local/sbin/agent-sudo-hostd`,
and a hardened systemd unit, then registers the host key. It never touches
`/usr/bin/sudo`: humans keep the normal sudo.

Requirements: `/etc/sudoers` (the policy ceiling) and a PAM service named `sudo`
(present wherever sudo or sudo-rs is installed). On Debian and Ubuntu the binary is
built with `sudo-i` as the PAM service for `sudo -i`, like the distro's sudo.

`agent-sudo-hostd status` checks configuration and connectivity.

### What hosts send

Every request carries the resolved command and arguments, user and target, working
directory, tty, the agent's optional explanation, and a session fingerprint derived
from `/proc` (the nearest ancestor that looks like a coding agent). Nothing is sent
for commands sudoers denies or allows without a password.

## 3. Agents

In each agent's environment (not your own shell):

```sh
agent-sudo-hostd shim install
export PATH="$HOME/.agent-tools:$PATH"
```

For Claude Code, putting the `export` in the environment that launches `claude` is
enough. The optional skill in `skills/agent-sudo/` teaches agents to add
`--agent-context "why"` and to wait patiently for approval.

## 4. Devices

- **iPhone / iPad**: open the service in Safari, Share → Add to Home Screen, open it
  from the Home Screen, sign in, Settings → This device → Turn on notifications.
- **Windows (Edge, Chrome)**: sign in and turn on notifications. Routine requests get
  Approve and Deny buttons right in the notification.
- **macOS Safari**: sign in and turn on notifications; Safari 16.4+ supports web push.

Every device appears under Settings → Signed-in devices and can be revoked there.
