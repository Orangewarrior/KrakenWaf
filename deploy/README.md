# KrakenWaf — Production Deployment Artifacts

Hardened, ready-to-adapt deployment manifests for running KrakenWaf in
production. Every artifact is aligned with the relevant **CIS Benchmark**
(systemd sandboxing, CIS Docker, CIS Kubernetes) and the principle of least
privilege: non-root, read-only root filesystem, all capabilities dropped, no
new privileges, seccomp `RuntimeDefault`, and an explicit writable allow-list.

```
deploy/
├── systemd/
│   └── krakenwaf.service        # sandboxed systemd unit (NoNewPrivileges, ProtectSystem=strict, …)
├── kubernetes/
│   ├── podsecurity.yaml         # namespace with Pod Security Admission "restricted"
│   ├── deployment.yaml          # Deployment + Services (non-root, RO rootfs, seccomp)
│   └── networkpolicy.yaml       # default-deny ingress/egress + explicit allows
└── docker/
    └── Containerfile            # multi-stage build → distroless/cc, non-root
```

## systemd

```bash
# 1. Create the service account and directories
sudo useradd --system --no-create-home --shell /usr/sbin/nologin krakenwaf
sudo install -d -o krakenwaf -g krakenwaf /var/lib/krakenwaf /var/log/krakenwaf
sudo install -d -o root -g root -m 0700 /etc/krakenwaf/secrets

# 2. Stage the binary, conf/, and rules/
sudo install -m 0755 target/release/krakenwaf /usr/local/bin/krakenwaf
sudo cp -r conf rules certs alert /var/lib/krakenwaf/

# 3. Install + start the unit
sudo cp deploy/systemd/krakenwaf.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now krakenwaf

# Verify the sandbox the unit actually got:
sudo systemd-analyze security krakenwaf
```

Key hardening directives: `NoNewPrivileges=true`, `ProtectSystem=strict`,
`ProtectHome=true`, `PrivateTmp=true`, `ReadWritePaths=/var/lib/krakenwaf
/var/log/krakenwaf`, `CapabilityBoundingSet=CAP_NET_BIND_SERVICE`,
`AmbientCapabilities=CAP_NET_BIND_SERVICE`, plus a `@system-service` syscall
allow-list and `MemoryDenyWriteExecute=true`. Secrets are delivered with
`LoadCredential=` (tmpfs, 0400) and consumed file-first via the matching
`<NAME>_FILE` env var (`REDIS_PASSWORD_FILE`, `BEARER_PASSWORD_FILE`,
`RORSCHACH_SECRET_EVEN_FILE`, `RORSCHACH_SECRET_ODD_FILE`).

`ExecStartPre` runs `krakenwaf config validate`, so the unit fails fast **before**
binding any port if a config file is invalid.

### Provision the secret source files (systemd)

```bash
sudo install -d -o root -g root -m 0700 /etc/krakenwaf/secrets
umask 0377   # new files are 0400 (root-only) by default

# Redis AUTH (only if distributed rate-limit / ban list is used).
printf '%s' "$REDIS_PASS" | sudo tee /etc/krakenwaf/secrets/REDIS_PASSWORD >/dev/null

# Observability bearer token (/metrics, health probes, kraken-ui) — opaque token.
openssl rand -hex 32 | sudo tee /etc/krakenwaf/secrets/BEARER_PASSWORD >/dev/null

# Rule-management (Rorschach) secrets — base64url (no padding), >= 64 random bytes.
openssl rand -base64 64 | tr '+/' '-_' | tr -d '=\n' \
  | sudo tee /etc/krakenwaf/secrets/RORSCHACH_SECRET_EVEN >/dev/null
openssl rand -base64 64 | tr '+/' '-_' | tr -d '=\n' \
  | sudo tee /etc/krakenwaf/secrets/RORSCHACH_SECRET_ODD >/dev/null

sudo chmod 0400 /etc/krakenwaf/secrets/*

# Or generate the same pair with the bundled helper:
cargo run --bin rorschach_keygen -- --dir /etc/krakenwaf/secrets
```

The unit ships the `LoadCredential=` / `Environment=<NAME>_FILE=` pairs for all
of these; remove the lines for any secret you do not use. The rule-management
control plane (`/rule/control/cmc/*`, port 4342) only opens when **both**
Rorschach secrets are present, and is **fail-closed**: a provisioned-but-invalid
secret aborts startup. See [`../docs/rule_management.md`](../docs/rule_management.md)
and [`../docs/secrets.md`](../docs/secrets.md).

## Kubernetes

Apply in order so the namespace policy gates admission:

```bash
kubectl apply -f deploy/kubernetes/podsecurity.yaml     # restricted namespace + LimitRange
kubectl apply -f deploy/kubernetes/networkpolicy.yaml   # default-deny + explicit allows

# Provide config / rules / TLS / secrets (adapt to your tooling):
kubectl -n krakenwaf create configmap krakenwaf-config --from-file=conf/
kubectl -n krakenwaf create configmap krakenwaf-rules  --from-file=rules/
kubectl -n krakenwaf create secret tls   krakenwaf-tls --cert=certs/server.crt --key=certs/server.key

# Generate the secret source files (file-first; never plaintext env):
openssl rand -hex 32                       > /tmp/BEARER_PASSWORD
openssl rand -base64 64 | tr '+/' '-_' | tr -d '=\n' > /tmp/RORSCHACH_SECRET_EVEN
openssl rand -base64 64 | tr '+/' '-_' | tr -d '=\n' > /tmp/RORSCHACH_SECRET_ODD

# Provision ALL secrets the deployment reads (drop REDIS_PASSWORD if unused).
kubectl -n krakenwaf create secret generic krakenwaf-secrets \
  --from-file=REDIS_PASSWORD=/path/to/redis-pass \
  --from-file=BEARER_PASSWORD=/tmp/BEARER_PASSWORD \
  --from-file=RORSCHACH_SECRET_EVEN=/tmp/RORSCHACH_SECRET_EVEN \
  --from-file=RORSCHACH_SECRET_ODD=/tmp/RORSCHACH_SECRET_ODD
shred -u /tmp/BEARER_PASSWORD /tmp/RORSCHACH_SECRET_EVEN /tmp/RORSCHACH_SECRET_ODD

kubectl apply -f deploy/kubernetes/deployment.yaml
```

The Secret is mounted file-first under `/run/secrets/krakenwaf/<NAME>` (never as
plaintext env). The Deployment exposes the rule-management control plane on port
**4342** via the `krakenwaf-rule-management` Service, and `networkpolicy.yaml`
only admits it from the `krakenwaf-admin` namespace. The shipped IP allowlist
(`rules/addr/allowlist/allow_rule_management.txt`) is **loopback-only**, so set
it to your management client's CIDR in the `krakenwaf-rules` ConfigMap before the
API will answer in-cluster (defence-in-depth on top of the Rorschach token).

Pod/container security context satisfies the **restricted** Pod Security
Standard: `runAsNonRoot: true`, `readOnlyRootFilesystem: true`,
`allowPrivilegeEscalation: false`, `capabilities.drop: ["ALL"]`, and
`seccompProfile.type: RuntimeDefault`. An init container runs
`krakenwaf config validate` to fail the rollout fast on a bad config. The
ServiceAccount token is not auto-mounted. Writable paths are `emptyDir`s only;
the root filesystem is read-only.

> The Deployment uses port **8443** so it needs **no** capability at all. If you
> must bind a privileged port (<1024), uncomment
> `capabilities.add: ["NET_BIND_SERVICE"]` in `deployment.yaml`.

## Docker / Podman

```bash
docker build -f deploy/docker/Containerfile -t krakenwaf:latest .

docker run --rm -p 8443:8443 -p 4343:4343 -p 4342:4342 \
    --read-only \
    --cap-drop ALL \
    --security-opt no-new-privileges \
    --tmpfs /tmp --tmpfs /var/lib/krakenwaf --tmpfs /var/log/krakenwaf \
    -v "$PWD/conf:/etc/krakenwaf/conf:ro" \
    -v "$PWD/rules:/etc/krakenwaf/rules:ro" \
    -v "$PWD/secrets/BEARER_PASSWORD:/run/secrets/krakenwaf/BEARER_PASSWORD:ro" \
    -v "$PWD/secrets/RORSCHACH_SECRET_EVEN:/run/secrets/krakenwaf/RORSCHACH_SECRET_EVEN:ro" \
    -v "$PWD/secrets/RORSCHACH_SECRET_ODD:/run/secrets/krakenwaf/RORSCHACH_SECRET_ODD:ro" \
    krakenwaf:latest
```

Each secret is mounted file-first as a single file under
`/run/secrets/krakenwaf/<NAME>`, which KrakenWaf resolves automatically — no
plaintext env required.

> Port **4342** is the rule-management control plane (`/rule/control/cmc/*`). It
> only opens when both `RORSCHACH_SECRET_*` files are present and is fail-closed.
> Generate the secret files first (`mkdir secrets`):
>
> ```bash
> openssl rand -hex 32                              > secrets/BEARER_PASSWORD
> openssl rand -base64 64 | tr '+/' '-_' | tr -d '=\n' > secrets/RORSCHACH_SECRET_EVEN
> openssl rand -base64 64 | tr '+/' '-_' | tr -d '=\n' > secrets/RORSCHACH_SECRET_ODD
> chmod 0400 secrets/*
> ```
>
> The `<NAME>_FILE` / plain-`<NAME>` environment variables are also accepted (see
> [`../docs/secrets.md`](../docs/secrets.md)), but prefer files in production —
> env vars leak via `/proc/<pid>/environ` and into child processes.

The image is a multi-stage build whose runtime layer is
`gcr.io/distroless/cc-debian12:nonroot` — no shell, no package manager, runs as
uid/gid 65532. The `HEALTHCHECK` runs `krakenwaf config validate`.

## Pre-flight validation

All three platforms wire in the same fail-fast gate. Run it manually any time:

```bash
krakenwaf config validate          # validate every conf/*.yaml + the rule set inputs
krakenwaf rules  validate          # parse rules/ and report rule counts
krakenwaf config dump --redact     # print the effective config with secrets masked
```
