#!/bin/sh
# Install agent-sudo on a host. Run as root from the directory holding the binaries.
#
#   sudo ./install.sh                         # install binaries and the systemd unit
#   sudo ./install.sh --enroll URL TOKEN      # ...and enroll with the approval service
#   sudo ./install.sh --uninstall
#
# This never touches /usr/bin/sudo. Agents opt in through a PATH shim:
#   agent-sudo-hostd shim install   (as the agent's user)
set -eu

here=$(cd "$(dirname "$0")" && pwd)
bin=/usr/local/bin/agent-sudo
sbin=/usr/local/sbin/agent-sudo-hostd
unit=/etc/systemd/system/agent-sudo-hostd.service

if [ "$(id -u)" -ne 0 ]; then
    echo "install.sh must run as root" >&2
    exit 1
fi

if [ "${1:-}" = "--uninstall" ]; then
    systemctl disable --now agent-sudo-hostd 2>/dev/null || true
    rm -f "$bin" "$sbin" "$unit"
    systemctl daemon-reload
    echo "Removed binaries and unit. /etc/agent-sudo (host key, config) was left in place."
    exit 0
fi

for f in agent-sudo agent-sudo-hostd agent-sudo-hostd.service; do
    [ -f "$here/$f" ] || { echo "missing $here/$f" >&2; exit 1; }
done

if [ ! -e /etc/pam.d/sudo ]; then
    echo "warning: /etc/pam.d/sudo does not exist; password fallback needs a PAM service named sudo" >&2
fi
if [ ! -e /etc/sudoers ] && [ ! -e /etc/sudoers-rs ]; then
    echo "error: no /etc/sudoers; agent-sudo uses the local sudoers as its policy ceiling" >&2
    exit 1
fi

install -o root -g root -m 0755 "$here/agent-sudo" "$bin"
# Set setuid explicitly after ownership: some install implementations (e.g. the Rust
# coreutils in newer Ubuntu) apply the owner after the mode, which clears the bit.
chown root:root "$bin"
chmod 4755 "$bin"
if [ ! -u "$bin" ]; then
    echo "error: could not set the setuid bit on $bin (is /usr/local mounted nosuid?)" >&2
    exit 1
fi
install -o root -g root -m 0755 "$here/agent-sudo-hostd" "$sbin"
install -o root -g root -m 0644 "$here/agent-sudo-hostd.service" "$unit"
install -d -o root -g root -m 0755 /etc/agent-sudo
systemctl daemon-reload
echo "Installed $bin (setuid) and $sbin."

if [ "${1:-}" = "--enroll" ]; then
    url=${2:?service URL}
    token=${3:?enrollment token}
    shift 3
    "$sbin" enroll --service "$url" --token "$token" "$@"
    systemctl enable --now agent-sudo-hostd
    sleep 1
    "$sbin" status
else
    echo "Next: $sbin enroll --service https://… --token …  &&  systemctl enable --now agent-sudo-hostd"
fi
