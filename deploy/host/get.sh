#!/bin/sh
# agent-sudo host installer, served by the approval service at /install.sh.
#
#   curl -fsSL https://SERVICE/install.sh | sudo sh -s -- --token TOKEN [--name NAME]
#   curl -fsSL https://SERVICE/install.sh | sudo sh      # upgrade an enrolled host
#
# Downloads the host bundle for this machine's architecture from the service,
# verifies it against the service's SHA256SUMS, installs it, enrolls this host
# with the one-time token, and starts the relay.
#
# Trust: this trusts the service you download from at install time. For stricter
# setups, build the bundle yourself (docker build --target host-dist) and run
# install.sh from it.
set -eu

SERVICE="__AGENT_SUDO_URL__"
token=""
name=""
while [ $# -gt 0 ]; do
    case "$1" in
        --token) token=${2:?}; shift 2 ;;
        --token=*) token=${1#--token=}; shift ;;
        --name) name=${2:?}; shift 2 ;;
        --name=*) name=${1#--name=}; shift ;;
        --service) SERVICE=${2:?}; shift 2 ;;
        *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
done

if [ "$(id -u)" -ne 0 ]; then
    echo "Run as root: curl -fsSL $SERVICE/install.sh | sudo sh -s -- --token TOKEN" >&2
    exit 1
fi
for tool in curl sha256sum install systemctl; do
    command -v "$tool" >/dev/null 2>&1 || { echo "missing required tool: $tool" >&2; exit 1; }
done

case "$(uname -m)" in
    x86_64 | amd64) arch=amd64 ;;
    aarch64 | arm64) arch=arm64 ;;
    *) echo "unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
echo "==> Downloading agent-sudo ($arch) from $SERVICE"
curl -fsSL "$SERVICE/dist/SHA256SUMS" -o "$tmp/SHA256SUMS"
if ! grep -q " $arch/agent-sudo\$" "$tmp/SHA256SUMS"; then
    echo "This service has no $arch binaries. Install with Homebrew instead:" >&2
    echo "  brew install tpurtell/local-ai/agent-sudo" >&2
    echo "  sudo \"\$(brew --prefix)/bin/agent-sudo-setup\" --enroll $SERVICE <token>" >&2
    exit 1
fi
mkdir "$tmp/$arch"
for f in agent-sudo agent-sudo-hostd agent-sudo-hostd.service install.sh; do
    curl -fsSL "$SERVICE/dist/$arch/$f" -o "$tmp/$arch/$f"
done
(cd "$tmp" && grep " $arch/" SHA256SUMS | sha256sum -c --quiet -) || {
    echo "checksum verification failed; not installing" >&2
    exit 1
}
chmod 755 "$tmp/$arch/install.sh"

if [ -e /etc/agent-sudo/hostd.toml ]; then
    echo "==> Already enrolled; upgrading binaries only"
    sh "$tmp/$arch/install.sh"
    systemctl restart agent-sudo-hostd
else
    [ -n "$token" ] || { echo "--token is required to enroll (Hosts → Add in the web app)" >&2; exit 2; }
    if [ -n "$name" ]; then
        sh "$tmp/$arch/install.sh" --enroll "$SERVICE" "$token" --name "$name"
    else
        sh "$tmp/$arch/install.sh" --enroll "$SERVICE" "$token"
    fi
fi
echo
echo "agent-sudo is installed. For each coding agent, as its user:"
echo "  agent-sudo-hostd shim install     # then put ~/.agent-tools first on the agent's PATH"
