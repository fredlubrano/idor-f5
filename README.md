# idor-f5 — BIG-IP Malicious User / IDOR aspiration detection (on-box)

Reproduce [F5 Distributed Cloud Malicious User Detection](https://docs.cloud.f5.com/docs-v2/web-app-and-api-protection/how-to/adv-security/malicious-users) behaviour on **F5 BIG-IP**, with a focus on **authenticated IDOR / API data aspiration**:

- Abuse signals → threat score **Low / Medium / High**
- **Cooling-off** that decays the level over idle time (default 20 minutes, XC-like)
- Progressive mitigation (JS challenge → harder challenge → temporary block / rate-limit)
- Optional **gemini-2.5-flash** enrichment via iRulesLX for ambiguous cases

The decision engine runs **on the BIG-IP** (iRules + session tables + iRulesLX). There is no external Python sidecar.

> WAF alone is not enough for working IDOR (many HTTP 200s). See [docs/WAF.md](docs/WAF.md) and [docs/ASPIRATION.md](docs/ASPIRATION.md).

## Documentation

| Doc | Content |
| --- | --- |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | On-box data path, session table, threat lifecycle |
| [docs/SIGNALS.md](docs/SIGNALS.md) | XC ↔ BIG-IP signal map + IDOR feature formulas |
| [docs/ASPIRATION.md](docs/ASPIRATION.md) | Authenticated user dumping the DB via API — how we detect it |
| [docs/AI.md](docs/AI.md) | gemini-2.5-flash contract, fail-open, circuit breaker |
| [docs/WAF.md](docs/WAF.md) | What ASM/WAF covers vs this behavioral layer |

## Layout

```
idor-f5 /
  config/default.yaml       # thresholds, paths, cooling-off, AI flags
  irules/malicious_user.tcl # scoring + IDOR counters + mitigation (templated)
  iruleslx/ai_enrich/       # Google Gemini enrich plugin (Node.js 6)
  scripts/render_irule.py   # inject YAML constants into the iRule
  scripts/deploy_rest.py    # iControl REST upload / attach
  lib/scoring.py            # pure Python mirror of scoring / IDOR features
  tests/                    # unit tests
  docs/                     # architecture, signals, aspiration, AI, WAF
```

## Quick start (lab)

```bash
python -m pip install -r requirements.txt
python -m pytest -q
```

1. Edit `config/default.yaml` (for aspiration set `identity.mode: jwt_sub`, object-path patterns, thresholds).
2. Render constants into the iRule:

   ```bash
   python scripts/render_irule.py --config config/default.yaml \
     --template irules/malicious_user.tcl \
     --out irules/malicious_user.rendered.tcl
   ```

3. Wrap for `tmsh load sys config merge` (do not commit the wrap; it is generated):

   ```bash
   { printf 'ltm rule malicious_user {\n'
     cat irules/malicious_user.rendered.tcl
     printf '\n}\n'
   } > irules/malicious_user.tmsh.conf
   ```

   On the BIG-IP: `tmsh load sys config merge file /var/tmp/malicious_user.tmsh.conf verify` then the same without `verify`. Re-attach the VS **without** dropping other iRules, e.g. `tmsh modify ltm virtual app_vs rules { other_rule malicious_user }`.

   Procedures must be invoked with `call mu_…`, not `[mu_…]`. On BIG-IP 21, `HTTP::uri` / `HTTP::path` / request `HTTP::header` inside a proc **plus** an `HTTP_RESPONSE` event can fail VS attach (`01071911`). Keep those reads in `HTTP_REQUEST` and store `mu_log_req` / `mu_log_client`.

4. Deploy with iControl REST (or paste the rendered iRule in TMUI):

   ```bash
   python scripts/deploy_rest.py --host https://bigip.lab --user admin \
     --irule irules/malicious_user.rendered.tcl --vs /Common/app_vs
   ```

   Or omit `--irule` to auto-render then upload. Copy `.env.example` → `.env` for credentials (never commit `.env`).

5. Optional AI: set `ai.enabled: true`, install the `iruleslx/ai_enrich` plugin (Node **6.9.1** on BIG-IP 21), store the Gemini key in `/config/gemini_api_key` (`chmod 600`, **not** `/var/tmp` — tmpfs wiped on reboot). ILX has no `env-vars` tmsh property; use `/config/startup` to copy the key back to `/var/tmp` at boot if the published plugin still reads that path. Allow egress HTTPS to `generativelanguage.googleapis.com`. Lab default is `ai.action: shadow` and `mitigation.shadow: true`. Plugin name `/Common/ai_enrich`, extension `ai_enrich`. Never commit the API key.

## LTM traces

Prefix `MU-IDOR`, facility `local0.warn`. Isolate with:

```bash
grep MU-IDOR /var/log/ltm
```

| Line | When |
| --- | --- |
| `MU-IDOR client=… req="GET /api/v1/dossiers/1" path_kind=0\|1 score=… level=… status=… ai=-|confirm|dismiss|boost|fail-open` | Every request that still hits TMM **after** scoring (`HTTP_RESPONSE`). `path_kind=1` if the path matches an object regex (`^/api/.+/\d+$`, …). `ai=-` if LX was not called. |
| `MU-IDOR-ACT client=… req="…" action=challenge\|block\|rate level=… score=…` | `HTTP_REQUEST` only when `mu_apply_mitigation` returns 1 |
| `mu_ai fail-open: …` | iRulesLX / Gemini error (unchanged, `log local0.`) |

No JWT, cookie, or body in these lines — client IP + request line, same idea as a BOLA deny log.

**API Protection PRP Reject** (profile type AP on the VS, no LTM ACCESS profile) **does not run `HTTP_RESPONSE`**. `ACCESS_*` events fail verify (`01071912`). The iRule logs that deny from `CLIENT_CLOSED` with `status=403` using values saved in `HTTP_REQUEST`. Score is **not** incremented on that path (no `HTTP::` from procs in `CLIENT_CLOSED`). A 401/403 that still reaches the backend **does** fire `HTTP_RESPONSE` and can raise the score.

Low mitigation is a local JS challenge: HTTP **503** HTML `Checking your browser`, cookie `mu_chal_l`, then `location.reload()`. `curl` never sets the cookie, so it keeps getting `MU-IDOR-ACT`. Medium adds a 1.5 s delay; High rejects or 429.

## How scoring works

| Layer | Role |
| --- | --- |
| **iRule Tcl** | Counts signals, updates per-user session-table state, applies mitigation synchronously |
| **session table** | `score`, threat `level`, cooling-off timers, IDOR counters, AI flags |
| **iRulesLX** | Outbound Gemini calls only when the AI gate opens (not on every request) |
| **ASM / LTM** | Optional feeds: WAF violations, denies, HTTP status |

**User key:** computed **once** in `HTTP_REQUEST` (`$mu_user_key`) and reused in `HTTP_RESPONSE` / `CLIENT_CLOSED`. Default is client IP. For authenticated IDOR aspiration set `identity.mode: jwt_sub` and pass an already-verified subject (`X-Authenticated-Sub` from APM / gateway) so counters are **per account**, not per NAT IP. The iRule does **not** decode unsigned JWT payloads.

IDOR thresholds (`distinct_ids`, `seq_ratio`, `forbid_ratio`, `success_enum`, `resp_bytes`, `rate_limit`) add points **once per sliding window** via `mu_award_once` (`mu:latch:${signal}:${user_key}`).

### Classic signals (XC-like)

- Forbidden activity (ASM deny / L7 reject)
- Failed login (401 on configured login paths)
- WAF activity (`ASM::violation`)
- Rate limiting (sliding window in iRule)

### IDOR / aspiration signals

Authenticated dumps often return **200** — 403/404 alone are not enough. The iRule tracks:

- distinct object IDs per template window
- sequential ID ratio
- template focus
- success-enum ratio (many 200 + many distinct IDs)
- aggregated response bytes
- forbid ratio when denials do appear

### Cooling-off & mitigation

After `scoring.cooling_off_minutes` without abuse, threat drops one step: High → Medium → Low → None.

| Level | Default action |
| --- | --- |
| Low | Local JavaScript challenge |
| Medium | Delayed / harder challenge |
| High | Temporary reject; optional hard rate-limit on object templates for authenticated aspiration |

Set `mitigation.shadow: true` to log decisions without challenging or blocking.

## AI (optional)

`gemini-2.5-flash` is **not** on the critical path. Gate opens on ambiguous score (or sampling). Returns `confirm | dismiss | boost` plus pattern hints (`data_aspiration`, `sequential_enum`, …). Fail-open on timeout/error; a local circuit breaker opens after 5 consecutive 429/5xx/timeouts.

Full option matrix (shadow, jwt_sub, dual_judge, local LLM, …): [docs/AI.md](docs/AI.md).

## Limits vs XC

- No tenant-wide ML or native IP reputation in v1
- Challenges are local (no reCAPTCHA yet)
- Gemini needs BIG-IP egress; keep AI gated to protect TPS
- The stack **detects / slows enumeration**; it does **not** fix application ownership (BOLA) bugs

## License / scope

Apache-friendly lab project (standalone). Conceptually inspired by F5 XC Malicious User docs and complementary to virtual-patch approaches; **no runtime dependency** on other repos. Not affiliated with F5, Inc.
