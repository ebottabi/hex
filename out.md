# Penetration Test Report
*Target:* `api.bitnob.com`
*Date:* 2026-05-19 17:16:49


## 1️⃣ DNS & Sub‑domain enumeration
---
Resolving target…
IP address: 18.130.137.132

---
### DNS records (dig)

; <<>> DiG 9.10.6 <<>> ANY api.bitnob.com +nocmd +noall +answer
;; global options: +cmd
api.bitnob.com.		60	IN	A	18.169.78.122
api.bitnob.com.		60	IN	A	13.135.224.245
api.bitnob.com.		60	IN	A	18.130.137.132

---
### Sub‑domains (amass passive)
