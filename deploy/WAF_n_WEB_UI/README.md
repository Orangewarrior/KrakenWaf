# KrakenWAF + Kraken UI vulnerable-application lab

This lab runs exactly two application containers or pods:

1. DVWA or OWASP Juice Shop as the intentionally vulnerable upstream.
2. KrakenWAF and Kraken UI together, with shared logs, credentials, metrics,
   and the live rule-management control plane.

The checked-in credentials and cryptographic keys are for local testing only.
Replace every value before adapting these manifests to a persistent or shared
environment.

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

The admin is created by Kraken UI's supported bootstrap environment. The
operator is created once through the authenticated, CSRF-protected ACL route.

## Kubernetes

Build the combined image and make it available to your cluster, then apply one
overlay:

```bash
docker build -f deploy/WAF_n_WEB_UI/Containerfile -t krakenwaf-ui-lab:2.46.0 .
kubectl apply -k deploy/WAF_n_WEB_UI/kubernetes/dvwa
```

For Juice Shop:

```bash
kubectl apply -k deploy/WAF_n_WEB_UI/kubernetes/juice-shop
```

Access the services locally:

```bash
kubectl port-forward service/kraken-waf-ui 8443:8443 3443:3443
```

The Kubernetes manifests use `emptyDir` storage and lab-only secrets. They are
deliberately disposable. Use PVCs and an external Secret provider before
retaining accounts, logs, or rule changes.
