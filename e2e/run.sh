#!/usr/bin/env bash
# Build the images, start the e2e environment, run the Playwright suite, tear down.
#   ./run.sh              full run
#   KEEP=1 ./run.sh       leave the environment running afterwards
#   ./run.sh -g "grant"   pass arguments to playwright test
set -euo pipefail
cd "$(dirname "$0")"
root=$(cd .. && pwd)
work=.work
mkdir -p "$work/certs"

if [ ! -f "$work/certs/ca.pem" ]; then
    echo "==> generating a throwaway test CA"
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 30 \
        -subj "/CN=agent-sudo e2e test CA" -keyout "$work/certs/ca.key" -out "$work/certs/ca.pem" 2>/dev/null
    openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj "/CN=sudo.e2e.test" \
        -keyout "$work/certs/server.key" -out "$work/certs/server.csr" 2>/dev/null
    printf "subjectAltName=DNS:sudo.e2e.test\nextendedKeyUsage=serverAuth\n" > "$work/certs/ext.cnf"
    openssl x509 -req -in "$work/certs/server.csr" -CA "$work/certs/ca.pem" -CAkey "$work/certs/ca.key" \
        -CAcreateserial -days 30 -extfile "$work/certs/ext.cnf" -out "$work/certs/server.pem" 2>/dev/null
    chmod 644 "$work/certs/"*.key
fi

pw_version=$(node -p "require('./node_modules/@playwright/test/package.json').version" 2>/dev/null || echo 1.55.0)
echo "==> building images (service, e2e host, runner with Playwright $pw_version)"
docker build -q -t agent-sudo-service:e2e --target service "$root" >/dev/null
docker build -q -t agent-sudo-host:e2e --target e2e-host "$root" >/dev/null
docker build -q -t agent-sudo-runner:e2e --build-arg PLAYWRIGHT_VERSION="$pw_version" -f runner.Dockerfile . >/dev/null

cleanup() { [ "${KEEP:-}" = 1 ] || docker compose down -v --remove-orphans >/dev/null 2>&1; }
trap cleanup EXIT
echo "==> starting the environment"
docker compose up -d --force-recreate --remove-orphans >/dev/null
for _ in $(seq 60); do
    docker compose exec -T runner node -e "fetch('https://sudo.e2e.test/api/health').then(r=>process.exit(r.ok?0:1),()=>process.exit(1))" >/dev/null 2>&1 && break
    sleep 1
done
echo "==> running tests"
docker compose exec -T runner npx playwright test "$@"
