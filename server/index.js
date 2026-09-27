/**
 * LinkGuard Server Entry Point
 * Production-ready Express API and static diagnostic client host.
 */

import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import { parseUrl } from './engine/parser.js';
import { runHeuristics, ALL_HEURISTICS, TARGET_BRANDS, SUSPICIOUS_TLDS, KNOWN_SHORTENERS } from './engine/heuristics.js';
import { calculateScore } from './engine/scoring.js';
import { resolveDns, unshortenUrl } from './engine/resolver.js';
import { runThreatIntelligence } from './engine/threatIntel.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const rootDir = path.resolve(__dirname, '..');

const app = express();
const PORT = process.env.PORT || 3000;

/**
 * In-memory API key store (never written to disk).
 * Keys are loaded from env vars on startup and can be updated at runtime.
 */
const API_KEYS = {
  virusTotal:        process.env.VIRUSTOTAL_API_KEY        || '',
  googleSafeBrowsing:process.env.GOOGLE_SAFE_BROWSING_KEY || '',
  urlScan:           process.env.URLSCAN_API_KEY           || ''
};

function maskKey(key) {
  if (!key || key.length < 8) return key ? '••••••••' : '';
  return key.slice(0, 4) + '••••••••' + key.slice(-4);
}

// Middleware
app.use(express.json({ limit: '1mb' }));
app.use(express.static(path.join(rootDir, 'public')));

// CORS headers for permissive local access
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept');
  if (req.method === 'OPTIONS') {
    return res.sendStatus(200);
  }
  next();
});

// Curated educational sample links
const SAMPLE_URLS = [
  {
    id: 'sample-benign-1',
    category: 'Legitimate / Benign',
    label: 'Standard Google Search',
    url: 'https://www.google.com/search?q=cybersecurity+defense',
    expectedRisk: 'Low',
    description: 'Clean HTTPS, legitimate root domain, normal length and entropy.'
  },
  {
    id: 'sample-benign-2',
    category: 'Legitimate / Benign',
    label: 'GitHub Linux Repository',
    url: 'https://github.com/torvalds/linux',
    expectedRisk: 'Low',
    description: 'Trusted platform, standard domain structure, verified SSL.'
  },
  {
    id: 'sample-phish-ip',
    category: 'Deceptive Host',
    label: 'IP-Literal Banking Gateway',
    url: 'http://192.168.1.45/secure-banking/login.php',
    expectedRisk: 'High',
    description: 'Bypasses DNS domain hierarchy entirely using raw IP address over unencrypted HTTP.'
  },
  {
    id: 'sample-phish-punycode',
    category: 'Visual Impersonation',
    label: 'Punycode PayPal Homoglyph',
    url: 'https://xn--pypal-4ve.com/signin/webapps/mpp/home',
    expectedRisk: 'High',
    description: 'Uses Cyrillic "а" to disguise "pypal" into looking identical to "paypal" in address bars.'
  },
  {
    id: 'sample-phish-subdomain',
    category: 'Brand Spoofing',
    label: 'Deep Subdomain Brand Burying',
    url: 'http://paypal.com.account-verification.notice-auth.secureserver.ga/login',
    expectedRisk: 'High',
    description: 'Buries brand name inside deep subdomains on a free/abused .ga top-level domain.'
  },
  {
    id: 'sample-phish-at',
    category: 'Syntax Trick',
    label: 'Browser @ Userinfo Redirection',
    url: 'https://www.chase.com@malicious-harvest-portal.xyz/verification',
    expectedRisk: 'High',
    description: 'Pretends to visit Chase, but browser sends credentials to the evil host following the "@" sign.'
  },
  {
    id: 'sample-phish-shortener',
    category: 'Obfuscated Destination',
    label: 'Masked Shortener Link',
    url: 'https://bit.ly/3xY8Z9',
    expectedRisk: 'Medium',
    description: 'Known shortener hides true destination from user inspection prior to navigation.'
  },
  {
    id: 'sample-phish-hyphen',
    category: 'Typosquatting',
    label: 'Hyphen-Stuffed Apple ID Scam',
    url: 'http://apple-id-security-recovery-center-login.com/auth',
    expectedRisk: 'High',
    description: 'Combines brand name impersonation with excessive hyphens on unencrypted HTTP.'
  }
];

/**
 * Primary URL Analysis Pipeline
 * @param {string} rawUrl
 * @param {object} options
 */
async function performAnalysis(rawUrl, options = {}) {
  const parsed = parseUrl(rawUrl);

  if (!parsed.isValid) {
    return {
      isValid: false,
      raw: rawUrl,
      error: parsed.parseError,
      score: 100,
      verdict: 'HIGH RISK',
      riskKey: 'high',
      badge: 'Malformed / Parse Failure',
      color: '#A63D3D',
      summary: `Unable to parse URL structure: ${parsed.parseError}. Malformed inputs are high risk.`,
      checks: []
    };
  }

  const checkResults = runHeuristics(parsed);
  const scored = calculateScore(checkResults);

  let enrichment = {
    dns: null,
    unshortened: null
  };

  // Safe server-side DNS resolution if requested or host is non-IP
  if (options.resolveDns && !parsed.isIp && parsed.host) {
    try {
      enrichment.dns = await resolveDns(parsed.host);
    } catch (err) {
      enrichment.dns = { resolved: false, error: err.message };
    }
  }

  // Safe unshortening probe if requested
  if (options.unshorten && (KNOWN_SHORTENERS.has(parsed.host) || KNOWN_SHORTENERS.has(parsed.rootDomain))) {
    try {
      enrichment.unshortened = await unshortenUrl(parsed.normalized, 3);
    } catch (err) {
      enrichment.unshortened = { success: false, error: err.message };
    }
  }

  return {
    isValid: true,
    url: parsed,
    ...scored,
    enrichment,
    analyzedAt: new Date().toISOString()
  };
}

// ─── Threat Intelligence Key Management ──────────────────────────

/**
 * GET /api/keys
 * Returns masked key status (present/absent) — never the real key value.
 */
app.get('/api/keys', (req, res) => {
  return res.json({
    virusTotal:         { configured: !!API_KEYS.virusTotal,         masked: maskKey(API_KEYS.virusTotal) },
    googleSafeBrowsing: { configured: !!API_KEYS.googleSafeBrowsing, masked: maskKey(API_KEYS.googleSafeBrowsing) },
    urlScan:            { configured: !!API_KEYS.urlScan,            masked: maskKey(API_KEYS.urlScan) }
  });
});

/**
 * POST /api/keys
 * Body: { virusTotal?: string, googleSafeBrowsing?: string, urlScan?: string }
 * Stores keys in-memory for this session.
 */
app.post('/api/keys', (req, res) => {
  const { virusTotal, googleSafeBrowsing, urlScan } = req.body || {};
  if (virusTotal         !== undefined) API_KEYS.virusTotal         = virusTotal.trim();
  if (googleSafeBrowsing !== undefined) API_KEYS.googleSafeBrowsing = googleSafeBrowsing.trim();
  if (urlScan            !== undefined) API_KEYS.urlScan            = urlScan.trim();

  return res.json({
    saved: true,
    virusTotal:         { configured: !!API_KEYS.virusTotal,         masked: maskKey(API_KEYS.virusTotal) },
    googleSafeBrowsing: { configured: !!API_KEYS.googleSafeBrowsing, masked: maskKey(API_KEYS.googleSafeBrowsing) },
    urlScan:            { configured: !!API_KEYS.urlScan,            masked: maskKey(API_KEYS.urlScan) }
  });
});

/**
 * POST /api/threat-check
 * Body: { url: string }
 * Runs VirusTotal + Google Safe Browsing + URLScan.io in parallel.
 */
app.post('/api/threat-check', async (req, res) => {
  try {
    const { url } = req.body || {};
    if (!url) return res.status(400).json({ error: 'Missing "url" property.' });

    const hasAnyKey = !!(API_KEYS.virusTotal || API_KEYS.googleSafeBrowsing || API_KEYS.urlScan);
    if (!hasAnyKey) {
      return res.status(200).json({
        noKeysConfigured: true,
        message: 'No API keys configured. Add keys via POST /api/keys or the Settings panel.'
      });
    }

    const report = await runThreatIntelligence(url, API_KEYS);
    return res.json({ url, ...report });
  } catch (err) {
    console.error('Threat intel error:', err);
    return res.status(500).json({ error: 'Threat intelligence lookup failed.', message: err.message });
  }
});

// REST Endpoints

/**
 * POST /api/analyze
 * Body: { url: string, resolveDns?: boolean, unshorten?: boolean }
 */
app.post('/api/analyze', async (req, res) => {
  try {
    const { url, resolveDns = true, unshorten = false, threatIntel = false } = req.body || {};

    if (!url) {
      return res.status(400).json({ error: 'Missing "url" property in request body.' });
    }

    const result = await performAnalysis(url, { resolveDns, unshorten });

    // Optionally enrich with threat intelligence if any key is configured
    if (threatIntel && (API_KEYS.virusTotal || API_KEYS.googleSafeBrowsing || API_KEYS.urlScan)) {
      result.threatIntel = await runThreatIntelligence(url, API_KEYS);
    } else if (threatIntel) {
      result.threatIntel = { noKeysConfigured: true };
    }

    return res.json(result);
  } catch (err) {
    console.error('Analysis error:', err);
    return res.status(500).json({ error: 'Internal server error during analysis.', message: err.message });
  }
});

/**
 * POST /api/batch
 * Body: { urls: string[] }
 */
app.post('/api/batch', async (req, res) => {
  try {
    const { urls } = req.body || {};

    if (!Array.isArray(urls)) {
      return res.status(400).json({ error: 'Property "urls" must be an array of URL strings.' });
    }

    const maxBatch = 50;
    const batch = urls.slice(0, maxBatch);

    const results = await Promise.all(
      batch.map(url => performAnalysis(url, { resolveDns: false, unshorten: false }))
    );

    const summary = {
      total: results.length,
      lowRisk: results.filter(r => r.riskKey === 'low').length,
      mediumRisk: results.filter(r => r.riskKey === 'medium').length,
      highRisk: results.filter(r => r.riskKey === 'high').length
    };

    return res.json({ summary, results });
  } catch (err) {
    console.error('Batch error:', err);
    return res.status(500).json({ error: 'Internal server error during batch scan.', message: err.message });
  }
});

/**
 * POST /api/unshorten
 * Body: { url: string }
 */
app.post('/api/unshorten', async (req, res) => {
  try {
    const { url } = req.body || {};
    if (!url) {
      return res.status(400).json({ error: 'Missing "url" property.' });
    }

    const result = await unshortenUrl(url, 3);
    return res.json(result);
  } catch (err) {
    return res.status(500).json({ error: 'Failed to unshorten URL.', message: err.message });
  }
});

/**
 * GET /api/heuristics
 * Returns list and metadata of the 10 checks
 */
app.get('/api/heuristics', (req, res) => {
  const dummyParsed = parseUrl('https://example.com');
  const dummyResults = runHeuristics(dummyParsed);

  const heuristicsMeta = dummyResults.map(h => ({
    id: h.id,
    label: h.label,
    category: h.category,
    weight: h.weight,
    description: h.explanation
  }));

  return res.json({
    totalCount: heuristicsMeta.length,
    trackedBrandsCount: Object.keys(TARGET_BRANDS).length,
    suspiciousTldsCount: SUSPICIOUS_TLDS.size,
    knownShortenersCount: KNOWN_SHORTENERS.size,
    heuristics: heuristicsMeta
  });
});

/**
 * GET /api/samples
 * Returns curated test examples
 */
app.get('/api/samples', (req, res) => {
  return res.json({ samples: SAMPLE_URLS });
});

/**
 * GET /api/health
 */
app.get('/api/health', (req, res) => {
  return res.json({
    status: 'ok',
    app: 'LinkGuard',
    version: '3.0.0',
    uptimeSeconds: Math.floor(process.uptime()),
    timestamp: new Date().toISOString(),
    threatIntel: {
      virusTotal:         !!API_KEYS.virusTotal,
      googleSafeBrowsing: !!API_KEYS.googleSafeBrowsing,
      urlScan:            !!API_KEYS.urlScan
    }
  });
});

// Fallback to index.html for single-page routing
app.get('*', (req, res) => {
  res.sendFile(path.join(rootDir, 'public', 'index.html'));
});

// Start Server
app.listen(PORT, () => {
  console.log(`===============================================`);
  console.log(`🛡️  LinkGuard Server listening on port ${PORT}`);
  console.log(`📡 URL: http://localhost:${PORT}`);
  console.log(`✨ Mode: Full-Stack (Offline-compatible frontend)`);
  console.log(`===============================================`);
});
