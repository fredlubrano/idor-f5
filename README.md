# idor-f5 — BIG-IP Malicious User / IDOR aspiration detection (on-box)

Reproduce [F5 Distributed Cloud Malicious User Detection](https://docs.cloud.f5.com/docs-v2/web-app-and-api-protection/how-to/adv-security/malicious-users) behaviour on **F5 BIG-IP**, with a focus on **authenticated IDOR / API data aspiration**:

- Abuse signals → threat score **Low / Medium / High**
- **Cooling-off** that decays the level over idle time (default 20 minutes, XC-like)
- Progressive mitigation (JS challenge → harder challenge → temporary block / rate-limit)
- Optional **gpt-4o-mini** enrichment via iRulesLX for ambiguous cases

The decision engine runs **on the BIG-IP** (iRules + session tables + iRulesLX). There is no external Python sidecar.

> WAF alone is not enough for working IDOR (many HTTP 200s). See [docs/WAF.md](docs/WAF.md) and [docs/ASPIRATION.md](docs/ASPIRATION.md).

## Documentation

| Doc | Content |
| --- | --- |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | On-box data path, session table, threat lifecycle |
| [docs/SIGNALS.md](docs/SIGNALS.md) | XC ↔ BIG-IP signal map + IDOR feature formulas |
| [docs/ASPIRATION.md](docs/ASPIRATION.md) | Authenticated user dumping the DB via API — how we detect it |
| [docs/AI.md](docs/AI.md) | gpt-4o-mini contract, fail-open, full option matrix |
| [docs/HUGGINGFACE.md](docs/HUGGINGFACE.md) | Build a **custom HF model** for aspiration IDOR |
| [docs/WAF.md](docs/WAF.md) | What ASM/WAF covers vs this behavioral layer |
| [ml/README.md](ml/README.md) | Dataset synthesis, train (sklearn/HF), classify API stub |

## Layout

```
idor-f5 /
  config/default.yaml       # thresholds, paths, cooling-off, AI flags
  irules/malicious_user.tcl # scoring + IDOR counters + mitigation (templated)
  iruleslx/ai_enrich/       # OpenAI enrich plugin (Node.js)
  as3/                      # optional VS + iRule attach (lab)
  scripts/render_irule.py   # inject YAML constants into the iRule
  scripts/deploy_rest.py    # iControl REST upload / attach
  lib/scoring.py            # pure Python mirror of scoring / IDOR features
  tests/                    # unit tests against lib/
  docs/                     # architecture, signals, aspiration, AI, HF, WAF
  ml/                       # custom Hugging Face / sklearn aspiration classifier
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

3. Deploy with iControl REST (or paste the rendered iRule in TMUI):

   ```bash
   python scripts/deploy_rest.py --host https://bigip.lab --user admin \
     --irule irules/malicious_user.rendered.tcl --vs /Common/app_vs
   ```

   Or omit `--irule` to auto-render then upload. Copy `.env.example` → `.env` for credentials (never commit `.env`).

4. Optional AI: set `ai.enabled: true`, install the `iruleslx/ai_enrich` plugin, store `OPENAI_API_KEY` on the BIG-IP / env, allow egress HTTPS to `api.openai.com` (or Azure/OpenAI). Start with `ai.action: shadow`.

## How scoring works

| Layer | Role |
| --- | --- |
| **iRule Tcl** | Counts signals, updates per-user session-table state, applies mitigation synchronously |
| **session table** | `score`, threat `level`, cooling-off timers, IDOR counters, AI flags |
| **iRulesLX** | Outbound GPT calls only when the AI gate opens (not on every request) |
| **ASM / LTM** | Optional feeds: WAF violations, denies, HTTP status |

**User key:** client IP by default. For authenticated IDOR aspiration set `identity.mode: jwt_sub` (or cookie/header) so counters are **per account**, not per NAT IP.

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

`gpt-4o-mini` is **not** on the critical path. Gate opens on ambiguous score (or sampling). Returns `confirm | dismiss | boost` plus pattern hints (`data_aspiration`, `sequential_enum`, …). Fail-open on timeout/error.

Full option matrix (shadow, jwt_sub, dual_judge, local LLM, …): [docs/AI.md](docs/AI.md).

## Limits vs XC

- No tenant-wide ML or native IP reputation in v1
- Challenges are local (no reCAPTCHA yet)
- GPT needs BIG-IP egress; keep AI gated to protect TPS
- The stack **detects / slows enumeration**; it does **not** fix application ownership (BOLA) bugs

## License / scope

Apache-friendly lab project (standalone). Conceptually inspired by F5 XC Malicious User docs and complementary to virtual-patch approaches; **no runtime dependency** on other repos. Not affiliated with F5, Inc.
