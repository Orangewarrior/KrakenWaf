# Real Client IP Behind Proxies: `--real-ip-header` and `--trusted-proxy-cidrs`

This document explains how these two KrakenWaf arguments work:

```bash
--real-ip-header X-Forwarded-For
--trusted-proxy-cidrs 127.0.0.1/32
```

They are used when KrakenWaf is **behind another proxy, load balancer, or CDN**.

---

## Why these arguments exist

When KrakenWaf receives a connection directly from a browser, the source IP is the real client IP.

Example:

```text
Client 203.0.113.10 -> KrakenWaf
```

In this case, KrakenWaf can trust the TCP peer address.

But when KrakenWaf is behind a reverse proxy, the TCP peer is usually the proxy, not the user:

```text
Client 203.0.113.10 -> Nginx/Cloudflare/ALB -> KrakenWaf
```

Without special handling, KrakenWaf would only see the proxy IP.

That breaks things like:

- rate limiting by client IP
- blocklists by IP
- attack attribution in logs
- analytics and incident response

So KrakenWaf needs a safe way to recover the **real client IP**.

---

## What `--real-ip-header` does

This tells KrakenWaf which HTTP header contains the original client IP.

Example:

```bash
--real-ip-header X-Forwarded-For
```

That means:

> "When a trusted proxy sends a request, inspect the `X-Forwarded-For` header and extract the original client IP from there."

Common header choices:

- `X-Forwarded-For`
- `X-Real-IP`
- `CF-Connecting-IP`

---

## What `--trusted-proxy-cidrs` does

This tells KrakenWaf **which source IPs are allowed to be trusted as proxies**.

Example:

```bash
--trusted-proxy-cidrs 127.0.0.1/32
```

That means:

> "Only accept `--real-ip-header` if the request came from 127.0.0.1."

This is critical for security.

If KrakenWaf trusted `X-Forwarded-For` from everyone, any attacker could send:

```http
X-Forwarded-For: 1.2.3.4
```

and fake their IP.

So the safe rule is:

1. Look at the real TCP peer IP.
2. Check if that peer IP belongs to a trusted proxy CIDR.
3. Only then trust the configured real IP header.

---

## The pair must be used together

These options are meant to work together.

### Good

```bash
--real-ip-header X-Forwarded-For \
--trusted-proxy-cidrs 127.0.0.1/32
```

### Bad

```bash
--real-ip-header X-Forwarded-For
```

Using `--real-ip-header` without restricting trusted proxies can allow IP spoofing.

---

## How KrakenWaf should think about it

KrakenWaf should treat the request source in this order:

1. TCP peer IP is the default source.
2. If TCP peer is in `--trusted-proxy-cidrs`, then KrakenWaf may trust `--real-ip-header`.
3. If not, ignore the header and keep the TCP peer IP.

---

# Practical examples

## 1. Localhost / local reverse proxy

### Scenario

You run KrakenWaf behind Nginx on the same machine:

```text
Client -> Nginx (127.0.0.1) -> KrakenWaf
```

### Recommended args

```bash
--real-ip-header X-Forwarded-For \
--trusted-proxy-cidrs 127.0.0.1/32
```

### Why

- Nginx is the trusted proxy
- Nginx connects to KrakenWaf from localhost
- KrakenWaf should only trust `X-Forwarded-For` when the peer is localhost

### Example

Incoming request to KrakenWaf:

```text
peer IP = 127.0.0.1
X-Forwarded-For: 203.0.113.50
```

Result:

- peer IP matches trusted CIDR
- header is trusted
- effective client IP becomes `203.0.113.50`

---

## 2. Nginx on a private LAN

### Scenario

Nginx runs on another machine in your LAN:

```text
Client -> Nginx (192.168.1.10) -> KrakenWaf
```

### Recommended args

```bash
--real-ip-header X-Forwarded-For \
--trusted-proxy-cidrs 192.168.1.10/32
```

Or, if you intentionally trust the whole subnet:

```bash
--real-ip-header X-Forwarded-For \
--trusted-proxy-cidrs 192.168.1.0/24
```

### Better choice

Prefer trusting the exact proxy IP when possible:

```bash
192.168.1.10/32
```

Instead of the whole subnet:

```bash
192.168.1.0/24
```

This reduces spoofing risk if another host in the subnet can reach KrakenWaf directly.

---

## 3. Cloudflare

### Scenario

Cloudflare sits in front of KrakenWaf.

Cloudflare usually sends the real client IP in:

```text
CF-Connecting-IP
```

### Recommended pattern

```bash
--real-ip-header CF-Connecting-IP \
--trusted-proxy-cidrs <Cloudflare CIDR ranges>
```

### Important

Do **not** trust `CF-Connecting-IP` from the public Internet.

Only trust it if the TCP peer belongs to Cloudflare's published IP ranges.

### Example

```text
peer IP = 173.245.x.x
CF-Connecting-IP: 198.51.100.20
```

If `173.245.x.x` is in your trusted Cloudflare CIDRs:

- trust the header
- effective client IP becomes `198.51.100.20`

If the peer is **not** in a trusted Cloudflare range:

- ignore the header
- effective client IP stays as the TCP peer IP

### Suggested note for docs

Store Cloudflare CIDRs in config management and update them when Cloudflare changes them.

---

## 4. AWS / Amazon Load Balancer

### Scenario

KrakenWaf is behind an AWS load balancer.

The most common header here is:

```text
X-Forwarded-For
```

### Recommended pattern

```bash
--real-ip-header X-Forwarded-For \
--trusted-proxy-cidrs <your ALB/NLB/VPC ranges>
```

### Notes

Trust only the IP ranges actually used by your load balancer or by the internal VPC path that reaches KrakenWaf.

If KrakenWaf is behind an internal ALB in a private subnet, you might trust those exact internal CIDRs.

### Example

```text
peer IP = 10.0.2.15
X-Forwarded-For: 198.51.100.88
```

If `10.0.2.15` is in a trusted proxy CIDR:

- header is trusted
- effective client IP becomes `198.51.100.88`

---

## 5. Direct exposure, no proxy

### Scenario

Clients connect directly to KrakenWaf.

### Recommended args

Do not use either argument.

### Why

There is no upstream proxy to trust.
The real client IP is already the TCP peer IP.

### Example

```text
Client 198.51.100.20 -> KrakenWaf
```

KrakenWaf should use `198.51.100.20` directly.

---

# Security guidance

## Prefer exact proxy IPs over broad ranges

Better:

```bash
--trusted-proxy-cidrs 127.0.0.1/32
```

or

```bash
--trusted-proxy-cidrs 192.168.1.10/32
```

Less safe:

```bash
--trusted-proxy-cidrs 192.168.1.0/24
```

Broader trust means broader spoofing surface.

---

## Never trust real IP headers from untrusted sources

If a request comes from an untrusted peer, KrakenWaf should ignore:

- `X-Forwarded-For`
- `X-Real-IP`
- `CF-Connecting-IP`

and any similar header.

---

## Treat malformed headers as suspicious

Examples:

- empty header
- invalid IP text
- multiple invalid values
- mixed private/public nonsense chains

Safe behavior:

- ignore malformed header
- keep peer IP
- optionally log a warning

---

# Header examples

## `X-Forwarded-For`

Example:

```http
X-Forwarded-For: 198.51.100.10
```

Or with multiple hops:

```http
X-Forwarded-For: 198.51.100.10, 203.0.113.7
```

In most setups, the leftmost value is the original client IP.
But KrakenWaf should document exactly how it parses multi-hop values.

---

## `X-Real-IP`

Example:

```http
X-Real-IP: 198.51.100.10
```

Usually simpler than `X-Forwarded-For`, but less standardized across proxy chains.

---

## `CF-Connecting-IP`

Example:

```http
CF-Connecting-IP: 198.51.100.10
```

Common when Cloudflare is the trusted edge.

---

# Suggested examples for Git docs

## Localhost example

```bash
krakenwaf \
  --listen 127.0.0.1:8443 \
  --upstream http://127.0.0.1:8080 \
  --allow-private-upstream \
  --real-ip-header X-Forwarded-For \
  --trusted-proxy-cidrs 127.0.0.1/32
```

## Cloudflare example

```bash
krakenwaf \
  --listen 0.0.0.0:8443 \
  --upstream http://10.0.0.20:8080 \
  --real-ip-header CF-Connecting-IP \
  --trusted-proxy-cidrs <cloudflare-cidrs>
```

## AWS ALB example

```bash
krakenwaf \
  --listen 0.0.0.0:8443 \
  --upstream http://10.0.1.25:8080 \
  --real-ip-header X-Forwarded-For \
  --trusted-proxy-cidrs <alb-private-cidrs>
```

---

# Recommended default mental model

Use these args only when KrakenWaf is **behind a trusted proxy**.

- `--real-ip-header` = which header contains the client IP
- `--trusted-proxy-cidrs` = which peers are allowed to assert that header

If you do not have a trusted proxy in front of KrakenWaf, do not use them.

---

# Short version for docs

```text
--real-ip-header tells KrakenWaf where to read the original client IP.
--trusted-proxy-cidrs tells KrakenWaf which proxy IPs are allowed to provide that header.
Only use them together.
```
