/**
 * iRulesLX plugin: ai_enrich
 * Calls OpenAI gpt-4o-mini to confirm / dismiss / boost IDOR-like behavior.
 * Fail-open: any error or timeout returns action "confirm" (deterministic score kept).
 *
 * Deploy as LX workspace/extension "ai_enrich".
 * Env: OPENAI_API_KEY (or MU_OPENAI_API_KEY). Never commit keys.
 */

'use strict';

const fs = require('fs');
const https = require('https');
const crypto = require('crypto');
const urlLib = require('url');

const MODEL = process.env.MU_AI_MODEL || 'gpt-4o-mini';
const ENDPOINT = process.env.MU_AI_ENDPOINT || 'https://api.openai.com/v1/chat/completions';
const TIMEOUT_MS = parseInt(process.env.MU_AI_TIMEOUT_MS || '800', 10);
const HASH_IDS = (process.env.MU_AI_HASH_IDS || 'true').toLowerCase() !== 'false';
const SHADOW = (process.env.MU_AI_SHADOW || 'false').toLowerCase() === 'true';

const SYSTEM_PROMPT = [
  'You are a security analyst judging whether an API client is performing',
  'IDOR / BOLA data aspiration or sequential object enumeration.',
  'You receive aggregated features only (no request bodies, no tokens, no passwords).',
  'Decide if the pattern looks like malicious enumeration vs legitimate sync/pagination/batch.',
  'Respond with ONLY a single JSON object matching this schema:',
  '{',
  '  "action": "confirm" | "dismiss" | "boost",',
  '  "threat": "low" | "medium" | "high",',
  '  "idor_likelihood": number between 0 and 1,',
  '  "pattern": "sequential_enum" | "sparse_probe" | "data_aspiration" | "legitim_batch" | "legitim_sync" | "unclear",',
  '  "reason": "one short sentence"',
  '}',
  'Rules:',
  '- confirm: keep the deterministic threat level.',
  '- dismiss: likely false positive (mobile sync, pagination, admin batch).',
  '- boost: clear IDOR/aspiration pattern; raise threat one level.',
  '- High idor_likelihood is valid even when forbid_ratio is near 0 (successful 200 enumeration).',
  '- Do not invent ownership; you only judge enumeration behavior.'
].join(' ');

function failOpen(reason) {
  return JSON.stringify({
    action: 'confirm',
    threat: 'low',
    idor_likelihood: 0,
    pattern: 'unclear',
    reason: reason || 'fail-open',
    fail_open: true,
    shadow: SHADOW
  });
}

function hashId(value) {
  if (!HASH_IDS || value === undefined || value === null || value === '') {
    return value;
  }
  return crypto.createHash('sha256').update(String(value)).digest('hex').slice(0, 16);
}

function sanitizeFeatures(raw) {
  let data;
  try {
    data = typeof raw === 'string' ? JSON.parse(raw) : raw;
  } catch (e) {
    return null;
  }

  const features = data.features || {};
  const out = {
    user_id: hashId(data.user_id || data.user || 'unknown'),
    score: Number(data.score) || 0,
    level: data.level || 'none',
    auth_present: Boolean(data.auth_present),
    features: {
      distinct_object_ids: Number(features.distinct_object_ids) || 0,
      sequential_ratio: Number(features.sequential_ratio) || 0,
      forbid_ratio: Number(features.forbid_ratio) || 0,
      ok_ratio: Number(features.ok_ratio) || 0,
      req_count: Number(features.req_count) || 0,
      response_bytes_sum: Number(features.response_bytes_sum) || 0,
      template_focus: Number(features.template_focus) || 0,
      aspiration_score: Number(features.aspiration_score) || 0,
      path_template: String(features.path_template || '').slice(0, 200),
      status_seq: String(features.status_seq || '').slice(0, 64)
    }
  };

  if (Array.isArray(features.sample_ids)) {
    out.features.sample_ids = features.sample_ids.slice(0, 20).map(hashId);
  }

  return out;
}

function buildUserPrompt(ctx) {
  const f = ctx.features;
  return [
    'API client behavioral snapshot:',
    `- user_key_hash: ${ctx.user_id}`,
    `- deterministic_score: ${ctx.score} (level=${ctx.level})`,
    `- auth_present: ${ctx.auth_present}`,
    `- distinct_object_ids: ${f.distinct_object_ids}`,
    `- sequential_ratio: ${f.sequential_ratio}`,
    `- forbid_ratio: ${f.forbid_ratio}`,
    `- ok_ratio: ${f.ok_ratio}`,
    `- req_count: ${f.req_count}`,
    `- response_bytes_sum: ${f.response_bytes_sum}`,
    `- template_focus: ${f.template_focus}`,
    `- aspiration_score: ${f.aspiration_score}`,
    `- path_template: ${f.path_template}`,
    `- status_seq: ${f.status_seq}`,
    '',
    'Question: IDOR/data aspiration / sequential enum, or legitimate sync/batch?',
    'Return JSON only.'
  ].join('\n');
}

function parseModelJson(content) {
  if (!content || typeof content !== 'string') {
    return null;
  }
  let text = content.trim();
  if (text.startsWith('```')) {
    text = text.replace(/^```(?:json)?\s*/i, '').replace(/\s*```$/, '');
  }
  try {
    return JSON.parse(text);
  } catch (e) {
    const m = text.match(/\{[\s\S]*\}/);
    if (m) {
      try {
        return JSON.parse(m[0]);
      } catch (e2) {
        return null;
      }
    }
    return null;
  }
}

function normalizeDecision(obj) {
  const actions = new Set(['confirm', 'dismiss', 'boost']);
  const threats = new Set(['low', 'medium', 'high']);
  const patterns = new Set([
    'sequential_enum',
    'sparse_probe',
    'data_aspiration',
    'legitim_batch',
    'legitim_sync',
    'unclear'
  ]);

  const action = actions.has(obj.action) ? obj.action : 'confirm';
  const threat = threats.has(obj.threat) ? obj.threat : 'low';
  let likelihood = Number(obj.idor_likelihood);
  if (Number.isNaN(likelihood)) {
    likelihood = 0;
  }
  likelihood = Math.max(0, Math.min(1, likelihood));
  const pattern = patterns.has(obj.pattern) ? obj.pattern : 'unclear';
  const reason = String(obj.reason || '').slice(0, 200) || 'no reason';

  return {
    action,
    threat,
    idor_likelihood: likelihood,
    pattern,
    reason,
    shadow: SHADOW,
    fail_open: false
  };
}

function loadApiKey() {
  if (process.env.OPENAI_API_KEY) {
    return process.env.OPENAI_API_KEY;
  }
  if (process.env.MU_OPENAI_API_KEY) {
    return process.env.MU_OPENAI_API_KEY;
  }
  const file = process.env.MU_AI_KEY_FILE ||
    '/var/ilx/workspaces/Common/ai_enrich/extensions/ai_enrich/openai.key';
  try {
    return fs.readFileSync(file, 'utf8').replace(/\s+/g, '');
  } catch (e) {
    return '';
  }
}

function callOpenAI(userPrompt) {
  return new Promise((resolve, reject) => {
    const apiKey = loadApiKey();
    if (!apiKey) {
      reject(new Error('missing OPENAI_API_KEY'));
      return;
    }

    const url = urlLib.parse(ENDPOINT);
    const body = JSON.stringify({
      model: MODEL,
      temperature: 0,
      max_tokens: 200,
      response_format: { type: 'json_object' },
      messages: [
        { role: 'system', content: SYSTEM_PROMPT },
        { role: 'user', content: userPrompt }
      ]
    });

    const req = https.request(
      {
        hostname: url.hostname,
        port: url.port || 443,
        path: (url.pathname || '/') + (url.search || ''),
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${apiKey}`,
          'Content-Length': Buffer.byteLength(body)
        },
        timeout: TIMEOUT_MS
      },
      (res) => {
        let data = '';
        res.on('data', (chunk) => {
          data += chunk;
        });
        res.on('end', () => {
          if (res.statusCode < 200 || res.statusCode >= 300) {
            reject(new Error(`openai HTTP ${res.statusCode}: ${data.slice(0, 200)}`));
            return;
          }
          try {
            const parsed = JSON.parse(data);
            const content =
              parsed.choices &&
              parsed.choices[0] &&
              parsed.choices[0].message &&
              parsed.choices[0].message.content;
            resolve(content);
          } catch (e) {
            reject(e);
          }
        });
      }
    );

    req.on('timeout', () => {
      req.destroy();
      reject(new Error('openai timeout'));
    });
    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

/**
 * Core enrich used by ILX RPC and local tests.
 * @param {string|object} rawPayload JSON from iRule
 * @returns {Promise<string>} JSON decision string
 */
function enrich(rawPayload) {
  const ctx = sanitizeFeatures(rawPayload);
  if (!ctx) {
    return Promise.resolve(failOpen('invalid payload'));
  }

  return callOpenAI(buildUserPrompt(ctx)).then((content) => {
    const parsed = parseModelJson(content);
    if (!parsed) {
      return failOpen('unparseable model output');
    }
    return JSON.stringify(normalizeDecision(parsed));
  }).catch((err) => {
    return failOpen(String(err && err.message ? err.message : err));
  });
}

// iRulesLX registration (on BIG-IP). Offline require() still exports helpers.
try {
  const f5 = require('f5-nodejs');
  const ilx = new f5.ILXServer();
  ilx.addMethod('enrich', (req, res) => {
    const payload = req.params()[0];
    enrich(payload)
      .then((out) => {
        res.reply(out);
      })
      .catch((err) => {
        res.reply(failOpen(String(err && err.message ? err.message : err)));
      });
  });
  ilx.listen();
} catch (e) {
  if (process.env.MU_AI_DEBUG) {
    // eslint-disable-next-line no-console
    console.error('ILXServer not started:', e.message);
  }
}

module.exports = {
  enrich,
  failOpen,
  sanitizeFeatures,
  parseModelJson,
  normalizeDecision,
  SYSTEM_PROMPT
};
