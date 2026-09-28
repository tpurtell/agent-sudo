# Playwright with the e2e test CA added to Chromium's NSS trust store, so WebAuthn
# runs against a genuinely trusted HTTPS origin (Chrome disables it on cert errors).
ARG PLAYWRIGHT_VERSION
FROM mcr.microsoft.com/playwright:v${PLAYWRIGHT_VERSION}-noble
RUN apt-get update && apt-get install -y --no-install-recommends libnss3-tools && rm -rf /var/lib/apt/lists/*
WORKDIR /e2e
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY .work/certs/ca.pem /usr/local/share/ca-certificates/agent-sudo-e2e.crt
RUN update-ca-certificates \
 && mkdir -p /root/.pki/nssdb && certutil -d sql:/root/.pki/nssdb -N --empty-password \
 && certutil -d sql:/root/.pki/nssdb -A -t "C,," -n agent-sudo-e2e -i /usr/local/share/ca-certificates/agent-sudo-e2e.crt
ENV NODE_EXTRA_CA_CERTS=/usr/local/share/ca-certificates/agent-sudo-e2e.crt
