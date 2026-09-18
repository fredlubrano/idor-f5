# Authenticated IDOR / data aspiration

## Scenario

An attacker has a **valid account** (login OK, JWT/cookie valid). They walk object APIs such as:

```http
GET /api/accounts/1
GET /api/accounts/2
GET /api/accounts/3
…
```

Because the app never checks ownership, responses are mostly **HTTP 200**. This is **not** SQLi, not login brute-force, and often **not** a WAF signature hit. The edge sees “clean” authenticated traffic while the client aspirates the database through the API.

## Why 403/404 are not enough

| If IDOR is… | Dominant edge signal |
| --- | --- |
| Broken (ownership enforced) | High **403/404** + many distinct IDs |
| **Working** (aspiration) | High **200** + many distinct IDs + volume/bytes + sequential patterns |

Detection must therefore combine **enumeration features** with **baseline deviation**, keyed by **authenticated identity** — not only Forbidden Activity.

## How abnormality is determined

```text
Authenticated session
        │
        ▼
Stable user key (prefer jwt_sub / session cookie — not IP alone)
        │
        ▼
Sliding window per user (e.g. 1–5 min + optional daily cap)
        │
        ├─ distinct_object_ids
        ├─ ids_per_minute / req_rate
        ├─ sequential_ratio
        ├─ template_focus
        ├─ success_enum (200 + distinct IDs)
        ├─ response_bytes_sum
        └─ baseline_deviation (vs that user’s history / static lab thresholds)
        │
        ▼
aspiration_score → Low / Medium / High
        │
        ├─ below gate → mitigate deterministically
        └─ ambiguous / sample → gpt-4o-mini confirm|dismiss|boost
```

### Deterministic signals (iRule)

| Signal | Abnormality (calibrate in YAML) | Captures |
| --- | --- | --- |
| `distinct_object_ids` | > N unique IDs / window on object templates | Mass DB walk via API |
| `ids_per_minute` | > user baseline × K | Sudden acceleration |
| `sequential_ratio` | High share of ±1 numeric steps | Scripted enum |
| `template_focus` | Most traffic on 1–2 `/api/.../{id}` templates | Targeted dump, not UI browse |
| `success_enum` / `ok_ratio` | Many **200** + many distinct IDs | **IDOR that works** |
| `response_bytes_sum` | Mo above p95 / static high | Volumetric exfil |
| `forbid_ratio` | When denials exist | Probing ownership |

Weighted mix (`idor.weights` in `config/default.yaml`):

```text
aspiration ≈ w_distinct·norm(ids) + w_rate·norm(rate)
           + w_seq·sequential_ratio + w_focus·template_focus
           + w_bytes·norm(bytes)
```

### What is *not* treated as abnormal (FP control)

- Normal pagination / UI browse (low rate, mixed templates)
- Short mobile sync bursts then idle
- Admin / batch roles via `identity.allowlist_subs` (attenuated scoring)

### Identity requirement

For this scenario set:

```yaml
identity:
  mode: jwt_sub   # or cookie_header
```

IP-only keys collapse many users behind NAT and miss per-account aspiration.

## AI role on this case

`gpt-4o-mini` receives **aggregated features only** (no bodies, no tokens). Prompt intent:

> Authenticated account; N distinct objects in T minutes; sequential ratio R; bytes B; template focus F — data aspiration vs legitimate sync?

Useful outputs beyond confirm/dismiss/boost:

- `pattern: data_aspiration | sequential_enum | legitim_sync | unclear`
- High `idor_likelihood` even when `forbid_ratio ≈ 0`

Prefer `ai.action: shadow` first in production to calibrate thresholds on real traffic.

## Mitigation when High = aspiration

Scripted exfiltrators often ignore JS challenges. For authenticated aspiration High:

1. **Hard rate-limit** on object templates for that user key  
2. **Temporary reject** / session block  
3. Later (out of scope v1): signal IdP to revoke the token  

Low/Medium may still use challenges + soft throttle for ambiguous cases.

## Recommended config order

1. `mitigation.shadow` / `ai.action: shadow` — observe  
2. `identity.mode: jwt_sub`  
3. Tune `idor.*` thresholds on lab traffic  
4. `ai.enabled: true` with `hash_ids`  
5. Enable live mitigation; optionally `dual_judge` later  

See also `docs/SIGNALS.md`, `docs/AI.md`, `docs/WAF.md`.
