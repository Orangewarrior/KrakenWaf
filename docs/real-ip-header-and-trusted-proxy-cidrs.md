# 🌐 Real Client IP Handling in KrakenWaf

When running KrakenWaf behind proxies, CDNs, or load balancers, you **must correctly handle the real client IP**.

This is done using:

```bash
--real-ip-header <HEADER>
--trusted-proxy-cidrs <CIDR>
```

---

## 🧠 Why This Matters

Without proper configuration, KrakenWaf will see:

```
Client → Proxy → KrakenWaf
```

And interpret the **proxy IP as the client IP** ❌

This breaks:

- 🚫 Rate limiting
- 🚫 IP blocking
- 🚫 Attack attribution
- 🚫 Logging accuracy

---

## ⚙️ How It Works

### 🔹 `--real-ip-header`

Defines which HTTP header contains the real client IP.

Example:

```bash
--real-ip-header X-Forwarded-For
```

📦 Common headers:
- `X-Forwarded-For`
- `X-Real-IP`
- `CF-Connecting-IP` (Cloudflare)

---

### 🔹 `--trusted-proxy-cidrs`

Defines **which IPs are allowed to be trusted as proxies**.

Example:

```bash
--trusted-proxy-cidrs 127.0.0.1/32
```

👉 KrakenWaf logic:

1. Check TCP peer IP  
2. If peer ∈ trusted CIDR → trust header  
3. Else → ignore header  

### Validated once, at startup (fail-fast)

The entries are **parsed and validated a single time at startup**, not on every
request. Two consequences:

- A **malformed entry is a hard boot error**, surfaced by `config validate` too.
  Previously a typo (e.g. `127.0.0.1/3X`) was silently dropped on each request —
  the proxy then looked like the client, and rate-limiting / banning /
  blocklisting all keyed on the **proxy** IP. That failure mode is gone.
- Both **CIDR** (`10.0.0.0/8`) and **bare IP literals** (`192.0.2.1`, treated as
  `/32`; `2001:db8::1` as `/128`) are accepted, so you can list single hosts
  without the `/32` suffix.

```text
# valid
--trusted-proxy-cidrs 10.0.0.0/8,192.0.2.1,2001:db8::/32

# invalid → WAF refuses to start with a clear error
--trusted-proxy-cidrs 127.0.0.1/3X
```

---

## 🔐 Security Rule (CRITICAL)

❗ Never trust headers blindly

If misconfigured, attacker can spoof IP:

```http
X-Forwarded-For: 1.2.3.4
```

👉 Always restrict trusted proxies

---

## ✅ Correct Usage

```bash
--real-ip-header X-Forwarded-For \
--trusted-proxy-cidrs 127.0.0.1/32
```

---

## ❌ Wrong Usage

```bash
--real-ip-header X-Forwarded-For
```

👉 This allows IP spoofing

---

# 🧪 Real-World Examples

## 🖥️ Localhost (Nginx Reverse Proxy)

```bash
--real-ip-header X-Forwarded-For \
--trusted-proxy-cidrs 127.0.0.1/32
```

---

## 🏠 LAN Proxy

```bash
--real-ip-header X-Forwarded-For \
--trusted-proxy-cidrs 192.168.1.10/32
```

---

## ☁️ Cloudflare

```bash
--real-ip-header CF-Connecting-IP \
--trusted-proxy-cidrs <cloudflare-ip-ranges>
```

---

## ☁️ AWS ALB

```bash
--real-ip-header X-Forwarded-For \
--trusted-proxy-cidrs <vpc-cidr>
```

---

## 🌍 Direct Exposure

👉 Do NOT use these flags

---

# 🛡️ Best Practices

- ✔ Always restrict trusted proxies  
- ✔ Prefer /32 over broad CIDR  
- ❌ Never trust public headers  
- ✔ Validate header format  

---

# 🧠 TL;DR

```
real-ip-header = where IP comes from
trusted-proxy-cidrs = who can be trusted
```
