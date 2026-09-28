# Deploying agent-sudo

Three pieces: the **approval service** (one per fleet, in Docker), **hostd** plus the
**agent-sudo** binary on each host, and your **devices** (any modern browser).

## 1. The approval service

Passkeys and Web Push need a stable HTTPS origin with a publicly trusted certificate.
The service does not need to be reachable from the Internet.

### Generate the deployment

`agent-sudo-service init` asks a few questions and writes a ready folder
(`docker-compose.yml`, `service.toml`, `.env` with mode 600, and the proxy config),
validated by the service's own parser. It can test your decision model live.

```sh
brew install tpurtell/local-ai/agent-sudo
agent-sudo-service init agent-sudo          # interactive; every answer also has a flag, --yes for scripts
cd agent-sudo && docker compose up -d
docker compose logs service | grep setup    # the one-time setup link
```

Without Homebrew, run the same command from the image:

```sh
docker run --rm -it --user "$(id -u):$(id -g)" -v "$PWD:/out" \
  ghcr.io/tpurtell/agent-sudo-service init /out/agent-sudo
```

`.env` sets `COMPOSE_PROFILES`, so `docker compose up -d` starts the right front door.
The image is published for amd64 and arm64 under one name; Docker picks the right one.

### Front door: Tailscale (recommended)

The sidecar joins your tailnet and serves `https://<name>.<tailnet>.ts.net` with an
automatic Let's Encrypt certificate. Only tailnet devices can reach it.

1. In the Tailscale admin console enable **MagicDNS** and **HTTPS certificates**.
2. Declare a tag for the service in your tailnet policy file, so the device belongs to
   the tag rather than a person and never expires:

   ```json
   "tagOwners": { "tag:agent-sudo": ["autogroup:admin"] }
   ```

3. Create an auth key under Settings → Keys → **Generate auth key**: not reusable, not
   ephemeral, pre-approved, with the tag `tag:agent-sudo`. `init` asks for it. It is
   only used for the first start.

`init` detects your tailnet's DNS suffix when `tailscale` is installed locally. The
machine name you choose becomes the service's address, and passkeys are tied to that
address for good. The device's identity is kept in the `tailscale` volume; back it up
with `data`, and never commit it anywhere.

**Without an auth key.** Leave it empty in `init` and the sidecar prints a login link
(`docker compose logs tailscale | grep login.tailscale.com`). Approve it, then choose
**Disable key expiry** for the device under Machines.

### Front door: your own certificate (nginx)

Choose nginx in `init`, give the exact `https://host:port` browsers will use, and point
it at `fullchain.pem` and `privkey.pem`.

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

Hosts → Add in the web app mints a one-time token and shows the commands. With
Homebrew (Linux amd64 and arm64 bottles):

```sh
brew install tpurtell/local-ai/agent-sudo
sudo "$(brew --prefix)/bin/agent-sudo-setup" --enroll https://agent-sudo.example.ts.net <token>
```

`agent-sudo` is setuid root and its relay runs as root, so neither may run from the
Homebrew prefix: your user, and every agent you run, can write there. The setup step
unpacks the host bundle, checks that the binaries use the system loader, embed no
library paths and need glibc 2.39 or older, and installs them root-owned:
`/usr/local/bin/agent-sudo` (setuid), `/usr/local/sbin/agent-sudo-hostd`, and a
hardened systemd unit. It never touches `/usr/bin/sudo`; humans keep the normal sudo.

After `brew upgrade agent-sudo`, run `sudo "$(brew --prefix)/bin/agent-sudo-setup"`
again. It keeps the host's enrollment and restarts the relay. `--uninstall` removes
the binaries and unit; `--check` verifies the bundle without root.

**Without Homebrew**, the sheet's second command downloads the bundle the service
carries for each architecture, verifies it against the service's `SHA256SUMS`, and runs
the same install:

```sh
curl -fsSL https://agent-sudo.example.ts.net/install.sh | sudo sh -s -- --token <token>
```

Either way requires `/etc/sudoers` (the policy ceiling) and a PAM service named `sudo`,
present wherever sudo or sudo-rs is installed. `agent-sudo-hostd status` checks
configuration and connectivity.

### What hosts send

Every request carries the resolved command and arguments, user and target, working
directory, tty, the agent's optional explanation, and a session fingerprint derived
from `/proc` (the nearest ancestor that looks like a coding agent). Nothing is sent
for commands sudoers denies or allows without a password.

## 3. Agents

As your own user (not root):

```sh
agent-sudo-hostd skill install       # the skill for every coding agent found; see AGENTS.md
agent-sudo-hostd shim install        # optional: makes plain `sudo` mean agent-sudo
export PATH="$HOME/.agent-tools:$PATH"   # in the agent's environment only
```

## 4. Devices

- **iPhone / iPad**: open the service in Safari, Share → Add to Home Screen, open it
  from the Home Screen, sign in, Settings → This device → Turn on notifications.
- **Windows (Edge, Chrome)**: sign in and turn on notifications. Routine requests get
  Approve and Deny buttons right in the notification.
- **macOS Safari**: sign in and turn on notifications; Safari 16.4+ supports web push.

Every device appears under Settings → Signed-in devices and can be revoked there.
