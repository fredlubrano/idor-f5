'use strict';

var https = require('https');
var http = require('http');
var url = require('url');
var fs = require('fs');
var crypto = require('crypto');

var DEFAULT_MODEL = process.env.MU_AI_MODEL || 'gemini-2.5-flash';
var DEFAULT_ENDPOINT =
  process.env.MU_AI_ENDPOINT ||
  'https://generativelanguage.googleapis.com/v1beta/models/' +
    encodeURIComponent(DEFAULT_MODEL) +
    ':generateContent';
var DEFAULT_TIMEOUT_MS = parseInt(process.env.MU_AI_TIMEOUT_MS || '800', 10);
var DEFAULT_HASH_IDS = (process.env.MU_AI_HASH_IDS || 'true').toLowerCase() !== 'false';
// /var/tmp is tmpfs on BIG-IP and is wiped on reboot. Prefer /config (persists).
var DEFAULT_KEY_FILES = [
  '/config/gemini_api_key',
  '/shared/gemini_api_key',
  '/var/tmp/gemini_api_key'
];
var DEFAULT_KEY_FILE = process.env.MU_AI_KEY_FILE || DEFAULT_KEY_FILES[0];

var VALID_ACTIONS = { confirm: true, dismiss: true, boost: true };
var VALID_THREATS = { low: true, medium: true, high: true };
var VALID_PATTERNS = {
  sequential_enum: true,
  sparse_probe: true,
  data_aspiration: true,
  legitim_batch: true,
  legitim_sync: true,
  unclear: true
};

var GEMINI_RESPONSE_SCHEMA = {
  type: 'OBJECT',
  properties: {
    action: {
      type: 'STRING',
      enum: ['confirm', 'dismiss', 'boost']
    },
    threat: {
      type: 'STRING',
      enum: ['low', 'medium', 'high']
    },
    idor_likelihood: {
      type: 'NUMBER'
    },
    pattern: {
      type: 'STRING',
      enum: [
        'sequential_enum',
        'sparse_probe',
        'data_aspiration',
        'legitim_batch',
        'legitim_sync',
        'unclear'
      ]
    },
    reason: {
      type: 'STRING'
    }
  },
  required: ['action', 'threat', 'idor_likelihood', 'pattern', 'reason']
};

var SYSTEM_INSTRUCTION =
  'You are an F5 BIG-IP API security analyzer detecting authenticated IDOR / BOLA ' +
  'and data aspiration campaigns. Analyze the telemetry features and return a JSON ' +
  'decision matching the schema: action (confirm|dismiss|boost), threat (low|medium|high), ' +
  'idor_likelihood (0.0 to 1.0), pattern (sequential_enum|sparse_probe|data_aspiration|' +
  'legitim_batch|legitim_sync|unclear), and a short one-sentence reason.';

var circuitBreaker = {
  failures: 0,
  threshold: 5,
  cooldownMs: 30000,
  openUntil: 0,
  isOpen: function () {
    return Date.now() < this.openUntil;
  },
  recordSuccess: function () {
    this.failures = 0;
    this.openUntil = 0;
  },
  recordFailure: function () {
    this.failures += 1;
    if (this.failures >= this.threshold) {
      this.openUntil = Date.now() + this.cooldownMs;
    }
  },
  reset: function () {
    this.failures = 0;
    this.openUntil = 0;
  }
};

function readKeyFile(path) {
  try {
    if (path && fs.existsSync(path)) {
      var value = fs.readFileSync(path, 'utf8').trim();
      if (value) {
        return value;
      }
    }
  } catch (e) {
    // ignore file read error
  }
  return '';
}

function loadApiKey(options) {
  if (options && options.apiKey) {
    return String(options.apiKey).trim();
  }
  if (process.env.GEMINI_API_KEY) {
    return String(process.env.GEMINI_API_KEY).trim();
  }
  if (process.env.GOOGLE_API_KEY) {
    return String(process.env.GOOGLE_API_KEY).trim();
  }
  if (options && options.keyFile) {
    return readKeyFile(options.keyFile);
  }
  if (process.env.MU_AI_KEY_FILE) {
    return readKeyFile(process.env.MU_AI_KEY_FILE);
  }
  var i;
  for (i = 0; i < DEFAULT_KEY_FILES.length; i += 1) {
    var fromFile = readKeyFile(DEFAULT_KEY_FILES[i]);
    if (fromFile) {
      return fromFile;
    }
  }
  return '';
}

function hashValue(val) {
  return 'sha256:' + crypto.createHash('sha256').update(String(val)).digest('hex').slice(0, 16);
}

function sanitizePayload(input, hashIds) {
  var copy = JSON.parse(JSON.stringify(input || {}));
  if (hashIds && copy.user_id) {
    copy.user_id = hashValue(copy.user_id);
  }
  if (hashIds && copy.features && Array.isArray(copy.features.sample_ids)) {
    copy.features.sample_ids = copy.features.sample_ids.map(hashValue);
  }
  return copy;
}

function failOpenResult(reason) {
  return {
    action: 'confirm',
    threat: 'low',
    idor_likelihood: 0.0,
    pattern: 'unclear',
    reason: reason || 'fail-open default',
    fail_open: true
  };
}

function validateDecision(obj) {
  if (!obj || typeof obj !== 'object') {
    return null;
  }
  var action = VALID_ACTIONS[obj.action] ? obj.action : null;
  var threat = VALID_THREATS[obj.threat] ? obj.threat : 'low';
  var pattern = VALID_PATTERNS[obj.pattern] ? obj.pattern : 'unclear';
  var likelihood = Number(obj.idor_likelihood);
  if (!action || isNaN(likelihood)) {
    return null;
  }
  if (likelihood < 0) likelihood = 0.0;
  if (likelihood > 1) likelihood = 1.0;

  return {
    action: action,
    threat: threat,
    idor_likelihood: likelihood,
    pattern: pattern,
    reason: typeof obj.reason === 'string' ? obj.reason.slice(0, 200) : '',
    fail_open: false
  };
}

function extractGeminiText(data) {
  var candidate = data && data.candidates && data.candidates[0];
  var part =
    candidate &&
    candidate.content &&
    candidate.content.parts &&
    candidate.content.parts[0];
  return part && part.text ? part.text : '';
}

function parseGeminiHttpBody(chunks) {
  var data = JSON.parse(chunks);
  var rawText = extractGeminiText(data);
  if (!rawText) {
    return failOpenResult('empty_gemini_candidate');
  }
  var parsedDecision = JSON.parse(rawText);
  var valid = validateDecision(parsedDecision);
  if (!valid) {
    return failOpenResult('invalid_gemini_schema');
  }
  return valid;
}

function buildGeminiRequestBody(sanitizedInput) {
  return JSON.stringify({
    systemInstruction: {
      parts: [{ text: SYSTEM_INSTRUCTION }]
    },
    contents: [
      {
        role: 'user',
        parts: [{ text: JSON.stringify(sanitizedInput) }]
      }
    ],
    generationConfig: {
      temperature: 0.0,
      maxOutputTokens: 256,
      responseMimeType: 'application/json',
      responseSchema: GEMINI_RESPONSE_SCHEMA,
      thinkingConfig: {
        thinkingBudget: 0
      }
    }
  });
}

function enrichWithGemini(payload, opts, callback) {
  if (typeof opts === 'function') {
    callback = opts;
    opts = {};
  }
  opts = opts || {};

  if (circuitBreaker.isOpen()) {
    return callback(null, failOpenResult('circuit_breaker_open'));
  }

  var apiKey = loadApiKey(opts);
  if (!apiKey) {
    return callback(null, failOpenResult('missing_gemini_api_key'));
  }

  var hashIds = opts.hashIds !== undefined ? Boolean(opts.hashIds) : DEFAULT_HASH_IDS;
  var timeoutMs = opts.timeoutMs || DEFAULT_TIMEOUT_MS;
  var model = opts.model || DEFAULT_MODEL;
  var endpoint =
    opts.endpoint ||
    'https://generativelanguage.googleapis.com/v1beta/models/' +
      encodeURIComponent(model) +
      ':generateContent';

  var parsedUrl;
  try {
    parsedUrl = url.parse(endpoint);
  } catch (e) {
    return callback(null, failOpenResult('invalid_endpoint_url'));
  }

  var sanitized = sanitizePayload(payload, hashIds);
  var bodyStr = buildGeminiRequestBody(sanitized);
  var isHttps = parsedUrl.protocol === 'https:';
  var transport = isHttps ? https : http;

  var reqOptions = {
    protocol: parsedUrl.protocol,
    hostname: parsedUrl.hostname,
    port: parsedUrl.port || (isHttps ? 443 : 80),
    path: parsedUrl.path,
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-goog-api-key': apiKey,
      'Content-Length': Buffer.byteLength(bodyStr)
    }
  };

  var finished = false;
  function done(result) {
    if (finished) return;
    finished = true;
    callback(null, result);
  }

  var req = transport.request(reqOptions, function (res) {
    var chunks = '';
    res.setEncoding('utf8');
    res.on('data', function (chunk) {
      chunks += chunk;
    });
    res.on('end', function () {
      if (res.statusCode === 429 || res.statusCode >= 500) {
        circuitBreaker.recordFailure();
        return done(failOpenResult('gemini_http_' + res.statusCode));
      }
      if (res.statusCode < 200 || res.statusCode >= 300) {
        return done(failOpenResult('gemini_http_' + res.statusCode));
      }

      try {
        var valid = parseGeminiHttpBody(chunks);
        if (valid && valid.fail_open) {
          return done(valid);
        }
        circuitBreaker.recordSuccess();
        return done(valid);
      } catch (err) {
        return done(failOpenResult('json_parse_error'));
      }
    });
  });

  req.setTimeout(timeoutMs, function () {
    circuitBreaker.recordFailure();
    req.abort();
    done(failOpenResult('gemini_timeout'));
  });

  req.on('error', function () {
    circuitBreaker.recordFailure();
    done(failOpenResult('gemini_network_error'));
  });

  req.write(bodyStr);
  req.end();
}

try {
  var f5 = require('f5-nodejs');
  var ilx = new f5.ILXServer();

  ilx.addMethod('enrich', function (req, res) {
    var rawArg = req.params() && req.params()[0];
    var payload = {};
    try {
      payload = typeof rawArg === 'string' ? JSON.parse(rawArg) : rawArg || {};
    } catch (e) {
      return res.reply(JSON.stringify(failOpenResult('bad_ilx_input')));
    }

    enrichWithGemini(payload, {}, function (_err, decision) {
      res.reply(JSON.stringify(decision));
    });
  });

  ilx.listen();
} catch (e) {
  // Hors BIG-IP
}

module.exports = {
  enrichWithGemini: enrichWithGemini,
  validateDecision: validateDecision,
  sanitizePayload: sanitizePayload,
  buildGeminiRequestBody: buildGeminiRequestBody,
  extractGeminiText: extractGeminiText,
  parseGeminiHttpBody: parseGeminiHttpBody,
  loadApiKey: loadApiKey,
  circuitBreaker: circuitBreaker,
  failOpenResult: failOpenResult,
  DEFAULT_KEY_FILES: DEFAULT_KEY_FILES,
  DEFAULT_KEY_FILE: DEFAULT_KEY_FILE
};
