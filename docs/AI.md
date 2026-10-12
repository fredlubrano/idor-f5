# AI enrich (gpt-4o-mini)

iRulesLX plugin `iruleslx/ai_enrich` judges ambiguous **IDOR / data-aspiration** cases.
It is **not** on every request — the iRule opens a gate (ambiguous score band or sampling) and never calls when High is already certain.

Reference product behaviour: [Enable Malicious User Detection and Mitigation (F5 XC)](https://docs.cloud.f5.com/docs-v2/web-app-and-api-protection/how-to/adv-security/malicious-users).

## Why AI for IDOR

IDOR/BOLA is usually **not** a malformed request: same method + path, valid body, often authenticated. ASM cannot answer “does this object belong to this caller?”.

What the edge *can* see is **enumeration / aspiration behaviour**. The iRule computes features; **gpt-4o-mini** judges whether the pattern looks like a dump campaign vs legitimate sync/pagination/admin batch.

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
    "template_focus": 0.9,
    "aspiration_score": 0.71,
    "path_template": "/api/accounts/{id}",
    "status_seq": "200,200,200,200"
  }
}
```

With `ai.privacy.hash_ids: true` (default), `user_id` and sample IDs are hashed before the OpenAI call.

**Output** (strict JSON):

```json
{
  "action": "confirm | dismiss | boost",
  "threat": "low | medium | high",
  "idor_likelihood": 0.0,
  "pattern": "sequential_enum | sparse_probe | data_aspiration | legitim_batch | legitim_sync | unclear",
  "reason": "one short sentence"
}
```

| Action | Effect on BIG-IP score |
| --- | --- |
| `confirm` | Keep deterministic level → normal mitigation |
| `dismiss` | Drop one threat level (likely false positive) |
| `boost` | Raise one level (clear IDOR / aspiration pattern) |

### What the AI does **not** do

- Prove ownership (impossible without app logic / token claims)  
- Replace the code fix (ownership check)  
- Block “victim object X” instead of the app — it constrains the **actor** who enumerates  

## Fail-open

Timeout, HTTP error, missing API key, or unparseable model output → `{ "action": "confirm", "fail_open": true }`.
Traffic continues under the iRule-only score.

## Shadow mode

`ai.action: shadow` (or `mitigation.shadow: true`): LX still returns a decision; the iRule logs `ai_shadow_action` and does **not** change score/mitigation. Use this to calibrate before enforcing.

## Env (deploy)

| Variable | Default |
| --- | --- |
| `OPENAI_API_KEY` | required when AI enabled |
| `MU_AI_MODEL` | `gpt-4o-mini` |
| `MU_AI_ENDPOINT` | `https://api.openai.com/v1/chat/completions` |
| `MU_AI_TIMEOUT_MS` | `800` |
| `MU_AI_HASH_IDS` | `true` |
| `MU_AI_SHADOW` | `false` |

## Options (`config/default.yaml` → `ai.*`)

| Option | IDOR / aspiration improvement | Cost / risk |
| --- | --- | --- |
| `ai.mode: enrich` (**MVP**) | confirm / dismiss / boost from features | Occasional latency; fail-open |
| `ai.mode: dual_judge` | Second opinion only when iRule vs heuristic diverge | +1 call; fewer FP |
| `ai.context.path_allowlist` | Only declared API templates sent to GPT | Less noise; needs config |
| `ai.context.openapi_hints` | Object paths from OpenAPI in the prompt | Better recall; needs spec |
| `ai` + `identity.mode: jwt_sub` | Per-account key behind NAT | Real BOLA multi-user; JWT parse |
| `identity.mode: cookie_header` | Session cookie / app header as key | App-specific |
| `ai.features.response_status_seq` | Status sequences including **200** runs | Strong aspiration signal |
| `ai.features.cross_account_hint` | Two sessions touching same IDs | Complex; session theft + enum |
| `ai.privacy.hash_ids` (**MVP**) | Hash IDs before OpenAI | Privacy; slightly less sequential detail |
| `ai.privacy.local_only_llm` | Internal endpoint (Azure/Ollama) | Air-gap; same JSON contract |
| `ai.action: shadow` (**MVP**) | Log AI decision without mitigating | Calibration |
| `ai.action: suggest_asm` | Emit suggested ASM/rate hardening (doc, not auto) | Bridge to virtual-patch style |
| `ai.memory.campaign_summary` | Rolling “this sub scans /api/vehicles/*” | Coherence; more state/tokens |
| `ai.calibration.feedback` | Operator FP/TP marks → thresholds / few-shot | Long-term quality |

**Suggested rollout:** shadow → path allowlist → jwt_sub → response_status_seq → dual_judge.

MVP implements: `enrich`, fail-open, `hash_ids`, shadow. Other flags are present/documented for progressive enablement.

See `docs/ASPIRATION.md` for the authenticated dump scenario and `docs/WAF.md` for why WAF alone is not enough.
