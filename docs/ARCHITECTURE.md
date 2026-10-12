# Architecture

On-box BIG-IP stack inspired by [F5 XC Malicious User Detection & Mitigation](https://docs.cloud.f5.com/docs-v2/web-app-and-api-protection/how-to/adv-security/malicious-users).

## Data path

```text
Client
  → Virtual Server
    → iRule (malicious_user)
         ├─ identity key (ip | jwt_sub | cookie)
         ├─ classic signals (401, 403, ASM, rate)
         ├─ IDOR / aspiration counters (session table)
         ├─ score → Low / Medium / High + cooling-off
         ├─ optional gate → iRulesLX ai_enrich → gpt-4o-mini
         └─ mitigate: JS challenge | harder challenge | rate-limit / reject
```

## Components

| Path | Role |
| --- | --- |
| `config/default.yaml` | Single source of thresholds, paths, AI flags |
| `irules/malicious_user.tcl` | Template iRule (`{{PLACEHOLDERS}}`) |
| `scripts/render_irule.py` | YAML → rendered Tcl constants |
| `scripts/deploy_rest.py` | iControl REST: upload iRule / LX, attach VS |
| `iruleslx/ai_enrich/` | Node.js plugin: OpenAI chat completions |
| `lib/scoring.py` | Pure-Python mirror for unit tests |
| `docs/*` | Signals, aspiration, AI, WAF comparison |

## Session table (per user key)

Typical keys under `session.table_prefix` (default `mu:`):

- `score`, `level`, `last_abuse_ts`
- IDOR: distinct ID set / count, sequential stats, bytes, status tallies, template hits
- AI: last action, shadow flag, cooldown before next call

## Threat lifecycle

1. **Accumulate** points from classic + aspiration signals  
2. **Map** score → Low / Medium / High  
3. **Cooling-off**: idle periods drop one level (default 20 minutes, XC-like)  
4. **Mitigate** according to level (or shadow-log only)  
5. **Retire** naturally via cooling-off when abuse stops  

## iRule events (BIG-IP 21)

Request commands (`HTTP::uri`, `HTTP::path`, request `HTTP::header`) are read **once** in `HTTP_REQUEST` into `mu_log_req` / `mu_log_client`. Logs live in events, not in procs. Existing procs are invoked with `call`.

| Event | Role |
| --- | --- |
| `HTTP_REQUEST` | Identity, cooling-off, rate, IDOR request track, pending AI apply, mitigation. Logs `MU-IDOR-ACT` only if mitigation returns 1. |
| `HTTP_RESPONSE` | Score 401/403, IDOR response features, optional iRulesLX, then always `MU-IDOR … status=[HTTP::status]`. |
| `CLIENT_CLOSED` | Fallback log when PRP Reject skipped `HTTP_RESPONSE` (api-protection VS has no LTM ACCESS profile). Uses saved request vars; `status=403`; no `HTTP::` / no scoring procs. |
| `ASM_REQUEST_DONE` / `ASM_REQUEST_BLOCKING` | Optional WAF points (`ASM::violation` needs a WEBSECURITY profile on the VS). |

`after` timers are cancelled when PRP closes TCP — do not use them for the deny log.

## Safety rules

- Never claim a control that does nothing: High aspiration prefers rate-limit/block over JS-only  
- AI is fail-open and gated (ambiguous band / sample; skip when High already certain)  
- Secrets stay in `.env` / BIG-IP — never in git  
- This layer **slows the actor**; it does **not** replace an application ownership check  
