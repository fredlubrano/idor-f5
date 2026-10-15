# Signals: XC Malicious User ↔ BIG-IP

Mapping from [F5 Distributed Cloud Malicious User Detection](https://docs.cloud.f5.com/docs-v2/web-app-and-api-protection/how-to/adv-security/malicious-users) to this on-box BIG-IP stack (`irules/malicious_user.tcl` + session tables).

## Classic XC-like signals

| XC signal | BIG-IP source | Config | Points key |
| --- | --- | --- | --- |
| Forbidden Activity | HTTP 403 (non-login), ASM deny | `signals.forbidden_activity` | `scoring.points.forbidden_activity` |
| Failed Login | 401/403 on login paths | `signals.failed_login.paths` | `scoring.points.failed_login` |
| WAF Activity | `ASM_REQUEST_DONE` / `ASM::violation` | `signals.waf_activity` | `scoring.points.waf_hit` |
| Rate Limiting | iRule sliding counter (`req_rate`) | `signals.rate_limiting` | `scoring.points.rate_limit` |
| IP Reputation | *v1 placeholder* | `signals.ip_reputation.enabled: false` | — |
| Bot Defense | *v1 placeholder* | `signals.bot_defense.enabled: false` | — |

User key v1: **client IP** (`identity.mode: ip`). For authenticated aspiration prefer `jwt_sub` or `cookie_header` so counters follow the account behind NAT.

## IDOR / data-aspiration features

Authenticated IDOR dumps often return **HTTP 200**. Forbidden/WAF alone miss that case. Per-user window (`idor.window_seconds`):

| Feature | Meaning | Typical anomaly |
| --- | --- | --- |
| `distinct_object_ids` | Unique IDs on object-path templates | Mass DB walk via `/api/.../{id}` |
| `ids_per_minute` | Distinct ID velocity | Sudden acceleration vs baseline |
| `sequential_ratio` | Share of ±1 numeric ID steps | Scripted enumeration |
| `template_focus` | Share of traffic on 1–2 templates | Targeted aspiration, not UI browse |
| `forbid_ratio` | 403/404 among object responses | Ownership probes (when denials exist) |
| `success_enum` / `ok_ratio` | Many **200** + many distinct IDs | **IDOR that works** |
| `response_bytes_sum` | Aggregated `Content-Length` | Volumetric exfil |
| `aspiration_score` | Weighted mix of the above | Maps to Low/Medium/High |

Object paths: regexes for `/api/.../<id>` (numeric or UUID-like). Templates are normalized to `.../{id}`.

Weighted aspiration (YAML `idor.weights`):

`w_distinct·norm(ids) + w_rate·norm(rate) + w_seq·seq + w_focus·focus + w_bytes·norm(bytes)`

When aspiration ≥ `aspiration_threshold` (or success-enum gates fire), the iRule adds aspiration points and may prefer **rate-limit then block** on High instead of a JS challenge (scripts ignore JS).

## Score → level → cooling-off → mitigation

1. Points accumulate into `score` (capped).
2. Level: Low / Medium / High from `scoring.thresholds`.
3. Cooling-off: each idle `scoring.cooling_off_minutes` (default **20**, XC-like) drops one level and resets score to that level’s threshold.
4. Mitigation (`mitigation.*`): Low = JS challenge, Medium = delayed/harder challenge, High = temp reject (+ optional object TPS limit for aspiration). `mitigation.shadow` / `ai.action: shadow` logs without blocking.

## WAF alone is not enough

ASM signatures, login brute-force, coarse rate limits, Bot Defense, and OpenAPI schema checks help, but **do not prove ownership** and often miss clean 200-OK aspiration. This project is the complementary **behavioral Malicious User–like** layer. Optional `waf_assisted` hardening (DoS on object URLs, OpenAPI, Bot, SIEM on volume-200) is documented in config — useful, not a substitute.

## Related

- `docs/AI.md` — when gemini-2.5-flash confirms / dismisses / boosts IDOR hypotheses
- `config/default.yaml` — all thresholds and flags
- `lib/scoring.py` — pure-Python mirror used by unit tests
