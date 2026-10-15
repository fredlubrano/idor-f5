# AI enrich (gemini-2.5-flash)

iRulesLX plugin `iruleslx/ai_enrich` judges ambiguous **IDOR / data-aspiration** cases.
It is **not** on every request — the iRule opens a gate (ambiguous score band or sampling) and never calls when High is already certain.

Reference product behaviour: [Enable Malicious User Detection and Mitigation (F5 XC)](https://docs.cloud.f5.com/docs-v2/web-app-and-api-protection/how-to/adv-security/malicious-users).

## Why AI for IDOR

IDOR/BOLA is usually **not** a malformed request: same method + path, valid body, often authenticated. ASM cannot answer “does this object belong to this caller?”.

What the edge *can* see is **enumeration / aspiration behaviour**. The iRule computes features; **gemini-2.5-flash** judges whether the pattern looks like a dump campaign vs legitimate sync/pagination/admin batch.

The plugin is **Node 6.9.1** compatible (BIG-IP 21): `var`, callbacks, no `async/await`, no object spread, native modules only (`https`, `http`, `url`, `fs`, `crypto`).

## Contract

**Input** (JSON from iRule, features only — no bodies/tokens):

```json
{
  "user_id": "ip:203.0.113.10",
  "score": 42,
  "level": "low",
  "auth_present": true,
  "features": {
    "distinct_object_ids": 35,
    "sequential_ratio": 0.82,
    "forbid_ratio": 0.05,
    "ok_ratio": 0.95,
    "req_count": 40,
    "response_bytes_sum": 8500000,
    "path_template": "/api/accounts/{id}"
  }
}
```

With `ai.privacy.hash_ids: true` (default), `user_id` and sample IDs are hashed before the Gemini call.

**Output** (strict JSON via Gemini structured outputs):

```json
{
  "action": "confirm | dismiss | boost",
  "threat": "low | medium | high",
  "idor_likelihood": 0.0,
  "pattern": "sequential_enum | sparse_probe | data_aspiration | legitim_batch | legitim_sync | unclear",
  "reason": "one short sentence"
}
```

Gemini is forced onto this schema with `generationConfig.responseMimeType = "application/json"` and `generationConfig.responseSchema`. Internal thinking is disabled (`thinkingConfig.thinkingBudget: 0`) to keep latency under 800 ms.

The plugin parses `candidates[0].content.parts[0].text` then validates the JSON.

| Action | Effect on BIG-IP score |
| --- | --- |
| `confirm` | Keep deterministic level → normal mitigation |
| `dismiss` | Drop one threat level (likely false positive) |
| `boost` | Raise one level (clear IDOR / aspiration pattern) |

The iRule applies that transition **once** in `HTTP_RESPONSE` (`mu_ai_apply_result`) and stores `mu:ai_last_action:$user_key` for audit. There is no `ai_pending_action` replay on the next `HTTP_REQUEST`.

### What the AI does **not** do

- Prove ownership (impossible without app logic / token claims)
- Replace the code fix (ownership check)
- Block “victim object X” instead of the app — it constrains the **actor** who enumerates

## Fail-open & circuit breaker

Timeout, HTTP 429/5xx, missing API key, or unparseable model output → `{ "action": "confirm", "threat": "low", "idor_likelihood": 0.0, "pattern": "unclear", "fail_open": true }`. Traffic continues under the iRule-only score.

Five consecutive 429/5xx/timeout/network failures open a local circuit breaker for 30 seconds so LX workers and TMM connections are not saturated.

## Shadow mode

`ai.action: shadow` (lab default) and `mitigation.shadow: true`: LX still returns a decision; the iRule logs `ai_shadow_action` and does **not** change score/mitigation. Use this to calibrate before `enforce`.

## Env (deploy)

| Variable | Default |
| --- | --- |
| `GEMINI_API_KEY` | inherited by the Node process if present (ILX tmsh has **no** `env-vars` property) |
| `GOOGLE_API_KEY` | fallback env |
| `MU_AI_KEY_FILE` | `/config/gemini_api_key` (persistent). Fallbacks: `/shared/gemini_api_key`, then `/var/tmp/gemini_api_key` (**tmpfs, lost on reboot**) |

Do **not** store the only copy in `/var/tmp`: BIG-IP tmpfs, empty after reboot. There is **no** `ilx plugin … env-vars` (Syntax Error: unknown property). Persist the key as a file on `/config` and restore `/var/tmp` at boot for the currently published plugin:

```bash
printf '%s' '<key>' > /config/gemini_api_key
chmod 600 /config/gemini_api_key
wc -c /config/gemini_api_key   # must be > 0, not an empty install /dev/null
cp -a /config/gemini_api_key /var/tmp/gemini_api_key
grep -q gemini_api_key /config/startup 2>/dev/null || cat >> /config/startup << 'EOF'
# Gemini key: /var/tmp is tmpfs (wiped on reboot)
if [ -s /config/gemini_api_key ]; then
  cp -a /config/gemini_api_key /var/tmp/gemini_api_key
  chmod 600 /var/tmp/gemini_api_key
fi
EOF
chmod 755 /config/startup
```
| `MU_AI_MODEL` | `gemini-2.5-flash` |
| `MU_AI_ENDPOINT` | `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent` |
| `MU_AI_TIMEOUT_MS` | `800` |
| `MU_AI_HASH_IDS` | `true` |

Auth header: `x-goog-api-key`. Never put the key in git.

## Options (`config/default.yaml` → `ai.*`)

| Option | IDOR / aspiration improvement | Cost / risk |
| --- | --- | --- |
| `ai.provider: google` (**MVP**) | Gemini generateContent | Egress to Google AI |
| `ai.mode: enrich` (**MVP**) | confirm / dismiss / boost from features | Occasional latency; fail-open |
| `ai.mode: dual_judge` | Second opinion only when iRule vs heuristic diverge | +1 call; fewer FP |
| `ai.context.path_allowlist` | Only declared API templates sent to Gemini | Less noise; needs config |
| `ai.context.openapi_hints` | Object paths from OpenAPI in the prompt | Better recall; needs spec |
| `ai` + `identity.mode: jwt_sub` | Per-account key via already-verified `X-Authenticated-Sub` | Real BOLA multi-user; no unsigned JWT decode |
| `identity.mode: cookie_header` | Session cookie / app header as key | App-specific |
| `ai.features.response_status_seq` | Status sequences including **200** runs | Strong aspiration signal |
| `ai.features.cross_account_hint` | Two sessions touching same IDs | Complex; session theft + enum |
| `ai.privacy.hash_ids` (**MVP**) | Hash IDs before Gemini | Privacy; slightly less sequential detail |
| `ai.privacy.local_only_llm` | Internal endpoint | Air-gap; same JSON contract |
| `ai.action: shadow` (**MVP**) | Log AI decision without mitigating | Calibration |
| `ai.action: suggest_asm` | Emit suggested ASM/rate hardening (doc, not auto) | Bridge to virtual-patch style |
| `ai.memory.campaign_summary` | Rolling “this sub scans /api/vehicles/*” | Coherence; more state/tokens |
| `ai.calibration.feedback` | Operator FP/TP marks → thresholds / few-shot | Long-term quality |

**Suggested rollout:** shadow → path allowlist → jwt_sub (trusted header) → response_status_seq → dual_judge.

MVP implements: Gemini enrich, structured JSON, thinkingBudget 0, fail-open, circuit breaker, `hash_ids`, shadow. Other flags are present/documented for progressive enablement.

See `docs/ASPIRATION.md` for the authenticated dump scenario and `docs/WAF.md` for why WAF alone is not enough.
