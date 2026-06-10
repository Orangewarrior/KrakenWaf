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
`LoadCredential=` (tmpfs, 0400) and consumed file-first via `REDIS_PASSWORD_FILE`.

`ExecStartPre` runs `krakenwaf config validate`, so the unit fails fast **before**
binding any port if a config file is invalid.

## Kubernetes

Apply in order so the namespace policy gates admission:

```bash
kubectl apply -f deploy/kubernetes/podsecurity.yaml     # restricted namespace + LimitRange
kubectl apply -f deploy/kubernetes/networkpolicy.yaml   # default-deny + explicit allows

# Provide config / rules / TLS / secrets (adapt to your tooling):
kubectl -n krakenwaf create configmap krakenwaf-config --from-file=conf/
kubectl -n krakenwaf create configmap krakenwaf-rules  --from-file=rules/
kubectl -n krakenwaf create secret tls   krakenwaf-tls --cert=certs/server.crt --key=certs/server.key
kubectl -n krakenwaf create secret generic krakenwaf-secrets --from-file=REDIS_PASSWORD=/path/to/redis-pass

kubectl apply -f deploy/kubernetes/deployment.yaml
```

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

docker run --rm -p 8443:8443 -p 4343:4343 \
    --read-only \
    --cap-drop ALL \
    --security-opt no-new-privileges \
    --tmpfs /tmp --tmpfs /var/lib/krakenwaf --tmpfs /var/log/krakenwaf \
    -v "$PWD/conf:/etc/krakenwaf/conf:ro" \
    -v "$PWD/rules:/etc/krakenwaf/rules:ro" \
    krakenwaf:latest
```

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
