'use strict';

var assert = require('assert');
var ai = require('./index.js');

function resetBreaker() {
  ai.circuitBreaker.reset();
}

function geminiEnvelope(decision) {
  return JSON.stringify({
    candidates: [
      {
        content: {
          parts: [{ text: JSON.stringify(decision) }]
        }
      }
    ]
  });
}

resetBreaker();

var parsed = ai.parseGeminiHttpBody(
  geminiEnvelope({
    action: 'boost',
    threat: 'high',
    idor_likelihood: 0.91,
    pattern: 'sequential_enum',
    reason: 'monotonic IDs with many 200s'
  })
);
assert.strictEqual(parsed.action, 'boost');
assert.strictEqual(parsed.threat, 'high');
assert.strictEqual(parsed.pattern, 'sequential_enum');
assert.strictEqual(parsed.idor_likelihood, 0.91);
assert.strictEqual(parsed.fail_open, false);

var extracted = ai.extractGeminiText(
  JSON.parse(
    geminiEnvelope({
      action: 'confirm',
      threat: 'low',
      idor_likelihood: 0.1,
      pattern: 'unclear',
      reason: 'ok'
    })
  )
);
assert.ok(extracted.indexOf('"action":"confirm"') !== -1 || extracted.indexOf('"action": "confirm"') !== -1);

var empty = ai.parseGeminiHttpBody(JSON.stringify({ candidates: [] }));
assert.strictEqual(empty.action, 'confirm');
assert.strictEqual(empty.fail_open, true);

var invalid = ai.validateDecision({ action: 'nuke', idor_likelihood: 0.2 });
assert.strictEqual(invalid, null);

var clamped = ai.validateDecision({
  action: 'dismiss',
  threat: 'medium',
  idor_likelihood: 4.2,
  pattern: 'legitim_sync',
  reason: 'batch job'
});
assert.strictEqual(clamped.idor_likelihood, 1.0);
assert.strictEqual(clamped.action, 'dismiss');

var fo = ai.failOpenResult('gemini_timeout');
assert.strictEqual(fo.action, 'confirm');
assert.strictEqual(fo.threat, 'low');
assert.strictEqual(fo.idor_likelihood, 0.0);
assert.strictEqual(fo.pattern, 'unclear');
assert.strictEqual(fo.fail_open, true);

var hashed = ai.sanitizePayload(
  { user_id: 'ip:203.0.113.10', features: { sample_ids: ['42'] } },
  true
);
assert.ok(String(hashed.user_id).indexOf('sha256:') === 0);
assert.ok(hashed.features.sample_ids[0].indexOf('sha256:') === 0);

var body = JSON.parse(
  ai.buildGeminiRequestBody({ user_id: 'sha256:abcd', score: 40, level: 'low' })
);
assert.strictEqual(body.generationConfig.responseMimeType, 'application/json');
assert.ok(body.generationConfig.responseSchema);
assert.strictEqual(body.generationConfig.thinkingConfig.thinkingBudget, 0);
assert.ok(body.generationConfig.responseSchema.required.indexOf('action') !== -1);

resetBreaker();
var i;
for (i = 0; i < 5; i += 1) {
  ai.circuitBreaker.recordFailure();
}
assert.strictEqual(ai.circuitBreaker.isOpen(), true);
ai.enrichWithGemini({ score: 40 }, { apiKey: 'unused' }, function (_err, decision) {
  assert.strictEqual(decision.fail_open, true);
  assert.strictEqual(decision.reason, 'circuit_breaker_open');
  assert.strictEqual(decision.action, 'confirm');
});

resetBreaker();
delete process.env.GEMINI_API_KEY;
delete process.env.GOOGLE_API_KEY;
ai.enrichWithGemini(
  { score: 40 },
  { keyFile: '/tmp/does-not-exist-mu-gemini-key' },
  function (_err, decision) {
    assert.strictEqual(decision.fail_open, true);
    assert.ok(decision.reason.indexOf('missing_gemini') !== -1);
  }
);

assert.strictEqual(ai.DEFAULT_KEY_FILE, '/config/gemini_api_key');
assert.strictEqual(ai.DEFAULT_KEY_FILES[0], '/config/gemini_api_key');
assert.ok(ai.DEFAULT_KEY_FILES.indexOf('/var/tmp/gemini_api_key') !== -1);

console.log('ok gemini unit tests');
