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
