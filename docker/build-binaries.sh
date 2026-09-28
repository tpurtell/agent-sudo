#!/bin/sh
# Build the service and the host binaries (agent-sudo, agent-sudo-hostd) natively for
# this architecture. Output: /out/agent-sudo-service and /out/dist/<arch>/.
# Other architectures are built natively on their own hosts (see RELEASING.md).
set -eu
arch=$(dpkg --print-architecture)
cargo build --release --locked -p agent-sudo-service -p agent-sudo-hostd
(cd sudo && cargo build --release --locked --features agent-approval,pam-login --bin sudo)
mkdir -p "/out/dist/$arch"
cp target/release/agent-sudo-service /out/
cp target/release/agent-sudo-hostd "/out/dist/$arch/"
cp sudo/target/release/sudo "/out/dist/$arch/agent-sudo"
cp deploy/host/install.sh deploy/host/agent-sudo-hostd.service "/out/dist/$arch/"
(cd /out/dist && sha256sum */* > SHA256SUMS)
echo "$arch" > /out/dist/NATIVE
