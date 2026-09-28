# syntax=docker/dockerfile:1.7
#
# Targets:
#   service     the approval service image (default)
#   host-dist   host binaries: docker build --target host-dist --output dist/ .
#   e2e-host    Ubuntu with a real sudoers/PAM setup, for the end-to-end tests
#
# Builds on Debian bookworm so the host binaries run on Ubuntu 22.04 and newer.

ARG RUST_VERSION=1

FROM node:24-bookworm-slim AS web
WORKDIR /web
COPY service/web/package.json service/web/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY service/web/ ./
RUN npm run build

FROM rust:${RUST_VERSION}-bookworm AS build
RUN apt-get update && apt-get install -y --no-install-recommends libpam0g-dev libssl-dev pkg-config && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
COPY --from=web /web/dist service/web/dist
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    --mount=type=cache,target=/src/sudo/target \
    cargo build --release --locked -p agent-sudo-service -p agent-sudo-hostd \
 && (cd sudo && cargo build --release --locked --features agent-approval,pam-login --bin sudo) \
 && mkdir -p /out \
 && cp target/release/agent-sudo-service target/release/agent-sudo-hostd /out/ \
 && cp sudo/target/release/sudo /out/agent-sudo

FROM scratch AS host-dist
COPY --from=build /out/agent-sudo /out/agent-sudo-hostd /
COPY deploy/host/ /

FROM debian:bookworm-slim AS service
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates libssl3 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 10001 --home /data --shell /usr/sbin/nologin agent-sudo \
 && mkdir -p /data /etc/agent-sudo && chown agent-sudo /data
COPY --from=build /out/agent-sudo-service /usr/local/bin/
USER agent-sudo
VOLUME /data
EXPOSE 8080
ENV AGENT_SUDO_CONFIG=/etc/agent-sudo/service.toml
HEALTHCHECK --interval=15s --timeout=5s --start-period=10s CMD ["agent-sudo-service", "health"]
ENTRYPOINT ["agent-sudo-service"]
CMD ["serve"]

FROM ubuntu:24.04 AS e2e-host
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      ca-certificates libpam-modules python3 expect procps && rm -rf /var/lib/apt/lists/* \
 && useradd --create-home --shell /bin/bash --uid 1500 agent \
 && useradd --create-home --shell /bin/bash --uid 1501 stranger \
 && echo 'agent:agent-password' | chpasswd
COPY --from=build /out/agent-sudo /usr/local/bin/agent-sudo
COPY --from=build /out/agent-sudo-hostd /usr/local/sbin/agent-sudo-hostd
COPY e2e/host/ /
RUN chmod 4755 /usr/local/bin/agent-sudo && chmod 0440 /etc/sudoers && chmod 0755 /usr/local/bin/e2e-* /etc/agent-sudo && chmod 0644 /etc/agent-sudo/client.conf /etc/pam.d/sudo /etc/pam.d/sudo-i
ENTRYPOINT ["/usr/local/bin/e2e-entrypoint"]
