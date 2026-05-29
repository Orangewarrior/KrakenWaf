#!/usr/bin/env bash
# Generate a local, self-signed TLS certificate for KrakenWaf development/demo.
#
# ⚠  NEVER use these in production. They are self-signed (CN=localhost) and the
#    private key sits unencrypted on disk. Production deployments must use
#    certificates issued by a real CA / ACME and mounted as secrets.
#
# Output (git-ignored, see .gitignore):
#   certs/cert.pem  — certificate, referenced by rules/tls/sni_map.csv
#   certs/key.pem   — private key (chmod 600)
set -euo pipefail

# Run from the repository root regardless of where the script is invoked.
cd "$(dirname "$0")/.."

mkdir -p certs

openssl req -x509 -nodes -days 365 -newkey rsa:4096 \
  -keyout certs/key.pem \
  -out certs/cert.pem \
  -config rules/tls/localhost.cnf

# Tighten the private key so it is not group/world readable (CIS Benchmark §1.2;
# the WAF warns at startup otherwise).
chmod 600 certs/key.pem

echo "✔ Generated certs/cert.pem and certs/key.pem (self-signed, CN=localhost)."
echo "  These files are git-ignored. Do NOT use them in production."
