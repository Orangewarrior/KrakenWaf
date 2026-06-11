# Production hardening — systemd, Kubernetes, Docker

KrakenWaf ships ready-to-adapt, **CIS-Benchmark-aligned** deployment artifacts
under [`deploy/`](../deploy). Every artifact applies the principle of least
privilege: non-root, read-only root filesystem, all capabilities dropped, no new
privileges, seccomp `RuntimeDefault`, and an explicit writable allow-list.

```
deploy/
├── systemd/krakenwaf.service          # sandboxed systemd unit
├── kubernetes/podsecurity.yaml        # restricted Pod Security Admission namespace
├── kubernetes/deployment.yaml         # Deployment + Services
├── kubernetes/networkpolicy.yaml      # default-deny ingress/egress + explicit allows
└── docker/Containerfile               # multi-stage → distroless/cc, non-root
```

A step-by-step install walkthrough lives in [`deploy/README.md`](../deploy/README.md);
this page documents the **why** behind each control.

---

## Cross-cutting principles

| Control | Rationale |
|---------|-----------|
| Run as a dedicated **non-root** account | A WAF is internet-facing; a process compromise must not be root. |
| **Read-only root filesystem** | Removes the ability to drop a webshell / tamper with the binary. Only an explicit writable allow-list (state + logs + `/tmp`) is mounted RW. |
| **Drop all capabilities** | The WAF needs none for ports ≥ 1024. Only `CAP_NET_BIND_SERVICE` is added when binding a privileged port (< 1024). |
| **No new privileges** | Blocks `setuid`/`setgid` escalation from any child process. |
| **seccomp `RuntimeDefault`** / syscall allow-list | Shrinks the kernel attack surface to the syscalls a network service actually uses. |
| **File-first secrets** | Secrets are mounted as files (tmpfs / projected volumes), never passed via environment — see [secrets.md](secrets.md). |
| **Fail-fast config validation** | `krakenwaf config validate` runs before the listener binds, so a bad config aborts the rollout instead of half-starting — see [admin_commands.md](admin_commands.md). |

---

## systemd — `deploy/systemd/krakenwaf.service`

The unit runs as the unprivileged `krakenwaf` account inside a tight systemd
sandbox. Key directives (the exact set requested for CIS-grade hardening):

```ini
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/krakenwaf /var/log/krakenwaf
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE
```

plus kernel/namespace lockdown (`ProtectKernelTunables`, `ProtectKernelModules`,
`ProtectControlGroups`, `ProtectClock`, `ProtectProc=invisible`,
`RestrictNamespaces`, `LockPersonality`, `MemoryDenyWriteExecute`,
`RestrictRealtime`, `RestrictSUIDSGID`, `RestrictAddressFamilies=AF_INET AF_INET6
AF_UNIX`), a `@system-service` syscall allow-list (with `@privileged`,
`@resources`, `@mount`, `@raw-io`, … denied), and resource caps
(`LimitNOFILE`, `TasksMax`, `MemoryMax`) as anti-DoS belt-and-braces.

Secrets are delivered with systemd credentials (tmpfs, `0400`, owned by the
service user) and consumed file-first:

```ini
LoadCredential=REDIS_PASSWORD:/etc/krakenwaf/secrets/REDIS_PASSWORD
Environment=REDIS_PASSWORD_FILE=%d/REDIS_PASSWORD
```

`ExecStartPre` runs `krakenwaf config validate`, so the unit fails **before**
binding any port if a config file is invalid. `ExecReload` sends `SIGHUP` to
hot-reload rules + TLS certificates.

Verify the realized sandbox after install:

```bash
sudo systemd-analyze security krakenwaf
```

---

## Kubernetes

Apply in order so the namespace policy gates admission:

```bash
kubectl apply -f deploy/kubernetes/podsecurity.yaml     # restricted PSA + LimitRange
kubectl apply -f deploy/kubernetes/networkpolicy.yaml   # default-deny + explicit allows
kubectl apply -f deploy/kubernetes/deployment.yaml      # Deployment + Services
```

### `podsecurity.yaml`

Labels the `krakenwaf` namespace for the built-in **Pod Security Admission**
`restricted` profile (`enforce`, `audit`, `warn`), with pinned versions so an
admission-controller upgrade cannot silently relax the policy. A `LimitRange`
bounds per-container CPU/memory so a mis-specified pod cannot request unbounded
resources.

### `deployment.yaml`

The pod/container security context satisfies the `restricted` standard:

```yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 10001
  readOnlyRootFilesystem: true
  allowPrivilegeEscalation: false
  privileged: false
  capabilities:
    drop: ["ALL"]
  seccompProfile:
    type: RuntimeDefault
```

Additional hardening: `automountServiceAccountToken: false`, a `config validate`
init container (fails the rollout on a bad config), `topologySpreadConstraints`
across nodes, `/livez` + `/readyz` probes, and writable paths provided **only**
as `emptyDir`s (state, logs, `/tmp`) so the root filesystem stays read-only.
Config / rules come from ConfigMaps; TLS + secrets from Secrets mounted `0400`
(secrets land under `/run/secrets/krakenwaf` for the file-first loader). A
dedicated metrics Service exposes the isolated observability port (4343).

> The Deployment uses port **8443**, so it needs **no** capability at all. To
> bind a privileged port (< 1024), uncomment `capabilities.add:
> ["NET_BIND_SERVICE"]`.

### `networkpolicy.yaml`

Three policies implementing CIS Kubernetes 5.3.2 (default-deny):

1. `default-deny-all` — denies all ingress + egress in the namespace.
2. `krakenwaf-allow-ingress` — data-plane `8443` from the ingress-controller
   namespace, metrics `4343` from the monitoring namespace.
3. `krakenwaf-allow-egress` — DNS (kube-dns), the upstream backend, and Redis
   (`6380`, TLS) only.

Adapt the selectors / namespaces / CIDRs to your topology. Requires a CNI that
enforces NetworkPolicy (Calico, Cilium, …).

---

## Docker / Podman — `deploy/docker/Containerfile`

A multi-stage build whose runtime layer is
`gcr.io/distroless/cc-debian12:nonroot` — no shell, no package manager, runs as
uid/gid 65532. The builder stage uses a full Rust toolchain (the build needs a C
compiler for the vendored libinjection and bundled SQLite); only the stripped
release binary plus default `conf/`, `rules/`, and `alert/` are copied into the
minimal runtime. The image `HEALTHCHECK` runs `config validate`.

Run it read-only with the matching runtime hardening:

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

---

## See also

* [deployment.md](deployment.md) — proxy topology, real-IP / trusted-proxy setup.
* [admin_commands.md](admin_commands.md) — `config validate` / `dump` / `rules validate`.
* [secrets.md](secrets.md) — the file-first secret-loading chain.
* [websocket.md](websocket.md) — WebSocket control policy.
* [`deploy/README.md`](../deploy/README.md) — copy-paste install walkthrough.
