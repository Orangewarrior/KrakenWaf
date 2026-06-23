# KrakenWAF + Kraken UI vulnerable-application lab

This lab runs exactly two application containers or pods:

1. DVWA or OWASP Juice Shop as the intentionally vulnerable upstream.
2. KrakenWAF, an embedded TLS-only Redis for distributed rate limiting, and
   Kraken UI together, with shared logs, credentials, metrics, and the live
   rule-management control plane.

The checked-in credentials and cryptographic keys are for local testing only.
Replace every value before adapting these manifests to a persistent or shared
environment.

The image builds a self-signed TLS certificate (CN=localhost) at build time when
`certs/cert.pem` / `certs/key.pem` are absent from the build context, so the lab
starts with no extra steps. Browsers and `curl` will flag the certificate as
untrusted (`curl -k`); supply your own pair in `certs/` before building, or mount
real certificates, for anything beyond local testing.

The image uses `debian:bookworm-slim` as the runtime base and also boots a
loopback-only Redis instance for the WAF and UI. The entrypoint generates a
dedicated local CA, a Redis server certificate, a least-privilege ACL user,
and the `REDIS_USERNAME` / `REDIS_PASSWORD` secret files under
`/run/secrets/krakenwaf/`. The WAF uses that Redis for both distributed rate
limiting and the BAN list; the UI uses the same hardened Redis for its global
rate-limit backend. All Redis traffic stays on `rediss://localhost:6380/0`
with a pinned CA and `fail_open: false`.

## Docker Compose

From the repository root, start the DVWA profile:

```bash
docker compose -f deploy/WAF_n_WEB_UI/compose.dvwa.yaml up --build
```

The protected DVWA endpoint is `https://localhost:8443`. The unprotected DVWA
container is not published to the host. This is equivalent to starting the
upstream directly with `docker run -d -p 8080:80 vulnerables/web-dvwa`, except
that Compose keeps it private to the lab network.

Start Juice Shop instead:

```bash
docker compose -f deploy/WAF_n_WEB_UI/compose.juice-shop.yaml up --build
```

The protected Juice Shop endpoint is `https://localhost:9443`. The Kraken UI
endpoint is `https://localhost:3443/kraken_ui/login` in both profiles.

Test accounts:

| Role | Username | Password |
|---|---|---|
| Administrator | `admin` | `Tentacle-Root!2026` |
| Operator | `operator` | `DeepCurrent!2026` |
| Auditor | `auditor` | `Audit-ReadOnly!2026` |

The admin is created by Kraken UI's supported bootstrap environment. The
operator and auditor are created through the authenticated, CSRF-protected ACL
route after the UI becomes healthy. To change the lab credentials before
starting Docker Compose, edit the `KRAKEN_UI_*_PASSWORD` and
`KRAKEN_UI_*_EMAIL` values in `compose.dvwa.yaml` or
`compose.juice-shop.yaml`.

## Kubernetes

The manifests include the same three lab users. To change them before applying
Kubernetes, edit `kubernetes/base/secret.yaml` for passwords and
`kubernetes/base/waf-ui.yaml` for emails.

Build the combined image and make it available to your cluster, then apply one
overlay:

```bash
docker build -f deploy/WAF_n_WEB_UI/Containerfile -t krakenwaf-ui-lab:2.47.0-bookworm-slim .
kubectl apply -k deploy/WAF_n_WEB_UI/kubernetes/dvwa
```

For Juice Shop:

```bash
kubectl apply -k deploy/WAF_n_WEB_UI/kubernetes/juice-shop
```

The lab uses PVCs for `/opt/krakenwaf/logs`, `/opt/kraken-ui/db`, and
`/opt/kraken-ui/log`, so UI accounts and WAF alerts survive pod restarts. The
entrypoint starts KrakenWAF first and waits until `db-waf-alerts`
(`/opt/krakenwaf/logs/db/vulns_alert.db`) exists before starting Kraken UI; this
keeps the dashboard and attack views available on first boot.

Access the services through the in-cluster Service:

```bash
kubectl port-forward service/kraken-waf-ui 8443:8443 3443:3443
```

Then open `https://127.0.0.1:3443/kraken_ui/login` for Kraken UI and
`https://127.0.0.1:8443/` for the protected app.

For a reusable local Fedora/Docker lab with k3s and persistent ports:

```bash
docker run -d --name krakenwaf-k3s \
  --privileged \
  --restart unless-stopped \
  -p 16443:6443 \
  -p 18080:80 \
  -p 18444:443 \
  -v krakenwaf-k3s-server:/var/lib/rancher/k3s \
  rancher/k3s:v1.31.0-k3s1 \
  server --tls-san 127.0.0.1 --disable traefik

docker exec krakenwaf-k3s cat /etc/rancher/k3s/k3s.yaml > /tmp/k3s-krakenwaf.yaml
sed -i 's|https://127.0.0.1:6443|https://127.0.0.1:16443|' /tmp/k3s-krakenwaf.yaml

docker build -f deploy/WAF_n_WEB_UI/Containerfile -t krakenwaf-ui-lab:2.47.0-bookworm-slim .
docker save krakenwaf-ui-lab:2.47.0-bookworm-slim vulnerables/web-dvwa:latest \
  | docker exec -i krakenwaf-k3s \
      ctr --address /run/k3s/containerd/containerd.sock --namespace k8s.io images import -

KUBECONFIG=/tmp/k3s-krakenwaf.yaml kubectl create namespace kraken-lab
KUBECONFIG=/tmp/k3s-krakenwaf.yaml kubectl -n kraken-lab apply -k deploy/WAF_n_WEB_UI/kubernetes/dvwa
```

The `kraken-waf-ui-host` LoadBalancer Service maps to those k3s container
ports. Open:

```text
Kraken UI: https://127.0.0.1:18080/kraken_ui/login
WAF/app:   https://127.0.0.1:18444/
```

If SELinux is enforcing, prefer Docker named volumes as shown above. For any
future host bind mount on Fedora, use Docker `:Z` or `:z` labels instead of
disabling SELinux.

The manifests contain lab-only secrets. Use an external Secret provider and
rotate every credential before adapting this setup to a shared environment.
