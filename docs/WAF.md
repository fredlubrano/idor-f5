# WAF alone vs this project

## Short answer

**Partially.** BIG-IP Advanced WAF / ASM (and classic WAAP controls) cover some *signals*, but they do **not** replace XC-style [Malicious User Detection](https://docs.cloud.f5.com/docs-v2/web-app-and-api-protection/how-to/adv-security/malicious-users) for **authenticated IDOR aspiration** (many clean **200** responses).

## What the WAF already does well

| WAF capability | Useful for | Limit vs aspiration IDOR |
| --- | --- | --- |
| Signatures / violations | Injection, malformed requests | IDOR requests are often **valid** → 0 hits |
| Brute-force / login | Repeated 401 | Attacker is **already** authenticated |
| Rate limit / L7 DoS | Global or URL velocity | Often **per IP**, not per `jwt_sub`; a slow user can still empty the DB |
| Bot Defense | Automation / scripts | Stolen token + “human” client bypasses |
| API / OpenAPI schema | Types, required, unknown fields | Does **not** check “this id belongs to this user” |
| ASM session tracking | Basic session anomalies | Rarely “N distinct object-ids vs user baseline” |
| Data Guard | Mask PAN/SSN in responses | Does not stop dumping business objects |

## What the WAF does not do (or does poorly) here

- **Ownership / BOLA** — application logic, not a WAF model  
- **Aspiration in 200 OK** — needs **behavioral baseline per auth identity**  
- **Malicious User (XC)** — F5 Distributed Cloud behavioral product; **no 1:1 declarative ASM policy** (same reason `virtual-patch-copilot` declines `malicious_user` on BIG-IP)  
- **gemini-2.5-flash judge** — not native to ASM; needs iRulesLX / external call  

## How the pieces fit

```text
ASM / WAF  ──signals──►  Behavioral score (per jwt_sub)
                              │
                              ├── gemini-2.5-flash enrich (optional)
                              └── Throttle / challenge / temp block
```

| Layer | Role |
| --- | --- |
| **WAF** | Sensors + generic brakes (rate, bot, schema) |
| **This repo** | Malicious User–like layer on BIG-IP: enumeration/aspiration score, cooling-off, mitigation, optional AI |

They are **complementary**, not substitutes. ASM hits can feed `waf_hits` points; turning “WAF on” is not IDOR aspiration detection.

## Degraded “max WAF, min custom” (`waf_assisted`)

Documented hardening if you cannot run the full iRule stack yet:

1. Tight DoS/rate profile on `/api/.../{id}` templates  
2. OpenAPI enforcement (noise reduction, **not** BOLA fix)  
3. Bot Defense on the same URLs  
4. SIEM alert on volume of 200s per session  

Useful hardening; **insufficient alone** for auth + DB dump via working IDOR.

Config placeholder: `waf_assisted` in `config/default.yaml`.
