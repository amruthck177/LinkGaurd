/**
 * LinkGuard — Threat Intelligence API Integrations
 * Supports: VirusTotal v3, Google Safe Browsing v4, URLScan.io
 *
 * All calls are made server-side to protect API keys.
 * Each integration degrades gracefully when the key is absent/invalid.
 */

// ─── VirusTotal v3 ────────────────────────────────────────────────
/**
 * Submit a URL to VirusTotal and retrieve scan results.
 * @param {string} url
 * @param {string} apiKey
 * @returns {Promise<object>}
 */
export async function checkVirusTotal(url, apiKey) {
  if (!apiKey) return { source: 'virustotal', skipped: true, reason: 'No API key configured' };

  try {
    // Step 1: Submit URL for scanning
    const urlId = Buffer.from(url).toString('base64').replace(/=/g, '');

    const submitRes = await fetch('https://www.virustotal.com/api/v3/urls', {
      method: 'POST',
      headers: {
        'x-apikey': apiKey,
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: `url=${encodeURIComponent(url)}`,
      signal: AbortSignal.timeout(8000)
    });

    if (!submitRes.ok) {
      const err = await submitRes.json().catch(() => ({}));
      return {
        source: 'virustotal',
        error: true,
        statusCode: submitRes.status,
        message: err?.error?.message || `HTTP ${submitRes.status}`
      };
    }

    const submitData = await submitRes.json();
    const analysisId = submitData?.data?.id;

    // Step 2: Fetch analysis report (may be cached)
    const reportRes = await fetch(`https://www.virustotal.com/api/v3/analyses/${analysisId}`, {
      headers: { 'x-apikey': apiKey },
      signal: AbortSignal.timeout(8000)
    });

    if (!reportRes.ok) {
      // Fall back: try URL lookup directly
      const lookupRes = await fetch(`https://www.virustotal.com/api/v3/urls/${urlId}`, {
        headers: { 'x-apikey': apiKey },
        signal: AbortSignal.timeout(8000)
      });

      if (!lookupRes.ok) {
        return { source: 'virustotal', error: true, message: `Lookup failed: HTTP ${lookupRes.status}` };
      }

      const lookupData = await lookupRes.json();
      return extractVtStats(lookupData?.data?.attributes?.last_analysis_stats, lookupData?.data?.attributes);
    }

    const reportData = await reportRes.json();
    return extractVtStats(reportData?.data?.attributes?.stats, reportData?.data?.attributes);

  } catch (err) {
    return { source: 'virustotal', error: true, message: err.message };
  }
}

function extractVtStats(stats, attrs) {
  if (!stats) return { source: 'virustotal', error: true, message: 'No stats returned' };

  const malicious  = stats.malicious  || 0;
  const suspicious = stats.suspicious || 0;
  const harmless   = stats.harmless   || 0;
  const undetected = stats.undetected || 0;
  const total = malicious + suspicious + harmless + undetected;

  const verdict = malicious >= 3 ? 'MALICIOUS'
                : malicious >= 1 ? 'SUSPICIOUS'
                : suspicious >= 3 ? 'SUSPICIOUS'
                : 'CLEAN';

  return {
    source: 'virustotal',
    verdict,
    malicious,
    suspicious,
    harmless,
    undetected,
    total,
    detectionRate: total ? `${malicious}/${total}` : '0/0',
    lastAnalysisDate: attrs?.last_analysis_date
      ? new Date(attrs.last_analysis_date * 1000).toISOString()
      : null,
    reputation: attrs?.reputation ?? null,
    categories: attrs?.categories ?? null
  };
}

// ─── Google Safe Browsing v4 ──────────────────────────────────────
/**
 * Check URL against Google Safe Browsing API.
 * @param {string} url
 * @param {string} apiKey
 * @returns {Promise<object>}
 */
export async function checkGoogleSafeBrowsing(url, apiKey) {
  if (!apiKey) return { source: 'google_safe_browsing', skipped: true, reason: 'No API key configured' };

  const endpoint = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${apiKey}`;

  const body = {
    client: { clientId: 'linkguard', clientVersion: '3.0.0' },
    threatInfo: {
      threatTypes: [
        'MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE',
        'POTENTIALLY_HARMFUL_APPLICATION', 'THREAT_TYPE_UNSPECIFIED'
      ],
      platformTypes: ['ANY_PLATFORM'],
      threatEntryTypes: ['URL'],
      threatEntries: [{ url }]
    }
  };

  try {
    const res = await fetch(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(6000)
    });

    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      return {
        source: 'google_safe_browsing',
        error: true,
        statusCode: res.status,
        message: err?.error?.message || `HTTP ${res.status}`
      };
    }

    const data = await res.json();
    const matches = data?.matches || [];

    if (matches.length === 0) {
      return { source: 'google_safe_browsing', verdict: 'CLEAN', threats: [], matchCount: 0 };
    }

    const threats = matches.map(m => ({
      type: m.threatType,
      platform: m.platformType,
      entryType: m.threatEntryType
    }));

    const isPhishing = threats.some(t => t.type === 'SOCIAL_ENGINEERING');
    const isMalware  = threats.some(t => t.type === 'MALWARE');

    return {
      source: 'google_safe_browsing',
      verdict: isMalware ? 'MALWARE' : isPhishing ? 'PHISHING' : 'THREAT_DETECTED',
      threats,
      matchCount: matches.length
    };

  } catch (err) {
    return { source: 'google_safe_browsing', error: true, message: err.message };
  }
}

// ─── URLScan.io ──────────────────────────────────────────────────
/**
 * Submit URL to URLScan.io and return scan metadata.
 * @param {string} url
 * @param {string} apiKey
 * @returns {Promise<object>}
 */
export async function checkUrlScan(url, apiKey) {
  if (!apiKey) return { source: 'urlscan', skipped: true, reason: 'No API key configured' };

  try {
    // Submit scan
    const submitRes = await fetch('https://urlscan.io/api/v1/scan/', {
      method: 'POST',
      headers: {
        'API-Key': apiKey,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ url, visibility: 'private' }),
      signal: AbortSignal.timeout(8000)
    });

    if (!submitRes.ok) {
      if (submitRes.status === 400) {
        // Try to search for existing scan instead
        return await searchUrlScan(url, apiKey);
      }
      const err = await submitRes.json().catch(() => ({}));
      return {
        source: 'urlscan',
        error: true,
        statusCode: submitRes.status,
        message: err?.message || `HTTP ${submitRes.status}`
      };
    }

    const submitData = await submitRes.json();
    const scanId = submitData?.uuid;
    const scanUrl = submitData?.result;

    // Wait briefly then fetch result (may not be ready yet)
    await new Promise(r => setTimeout(r, 3500));

    if (scanId) {
      const resultRes = await fetch(`https://urlscan.io/api/v1/result/${scanId}/`, {
        signal: AbortSignal.timeout(8000)
      });

      if (resultRes.ok) {
        const resultData = await resultRes.json();
        return extractUrlScanResult(resultData, scanUrl);
      }
    }

    return {
      source: 'urlscan',
      verdict: 'PENDING',
      scanId,
      scanUrl,
      note: 'Scan submitted. Results may take 10-30s. Check URLScan.io directly.'
    };

  } catch (err) {
    return { source: 'urlscan', error: true, message: err.message };
  }
}

async function searchUrlScan(url, apiKey) {
  try {
    const domain = new URL(url).hostname;
    const searchRes = await fetch(
      `https://urlscan.io/api/v1/search/?q=domain:${domain}&size=1&sort=date`,
      { headers: { 'API-Key': apiKey }, signal: AbortSignal.timeout(6000) }
    );
    if (!searchRes.ok) return { source: 'urlscan', error: true, message: `Search HTTP ${searchRes.status}` };

    const searchData = await searchRes.json();
    const hit = searchData?.results?.[0];

    if (!hit) return { source: 'urlscan', verdict: 'NO_PRIOR_SCAN', note: `No previous scans for ${domain}` };

    return {
      source: 'urlscan',
      verdict: hit?.verdicts?.overall?.malicious ? 'MALICIOUS' : 'CLEAN',
      malicious: hit?.verdicts?.overall?.malicious,
      score: hit?.verdicts?.overall?.score,
      tags: hit?.verdicts?.overall?.tags,
      scanDate: hit?.task?.time,
      screenshotUrl: hit?.screenshot,
      scanUrl: hit?.result
    };
  } catch (err) {
    return { source: 'urlscan', error: true, message: err.message };
  }
}

function extractUrlScanResult(data, scanUrl) {
  const verdict = data?.verdicts?.overall;
  return {
    source: 'urlscan',
    verdict: verdict?.malicious ? 'MALICIOUS' : 'CLEAN',
    malicious: verdict?.malicious,
    score: verdict?.score,
    tags: verdict?.tags,
    brands: verdict?.brands,
    country: data?.page?.country,
    ip: data?.page?.ip,
    server: data?.page?.server,
    asnName: data?.page?.asnname,
    tlsIssuer: data?.page?.tlsIssuer,
    redirectedTo: data?.page?.url !== data?.task?.url ? data?.page?.url : null,
    domMutations: data?.stats?.domainStats?.length,
    screenshotUrl: data?.task?.screenshotURL,
    scanUrl
  };
}

// ─── Aggregate Threat Report ─────────────────────────────────────
/**
 * Run all configured threat intelligence checks in parallel.
 * Returns a combined threat report with an overall verdict.
 */
export async function runThreatIntelligence(url, keys = {}) {
  const [vt, gsb, us] = await Promise.all([
    checkVirusTotal(url, keys.virusTotal),
    checkGoogleSafeBrowsing(url, keys.googleSafeBrowsing),
    checkUrlScan(url, keys.urlScan)
  ]);

  const sources = [vt, gsb, us];
  const active  = sources.filter(s => !s.skipped && !s.error);
  const threats  = active.filter(s => s.verdict && !['CLEAN', 'PENDING', 'NO_PRIOR_SCAN'].includes(s.verdict));

  let overallVerdict = 'CLEAN';
  let overallSeverity = 0;

  if (threats.length > 0) {
    const hasMalware  = threats.some(s => s.verdict === 'MALWARE' || s.verdict === 'MALICIOUS');
    const hasPhishing = threats.some(s => s.verdict === 'PHISHING' || s.verdict === 'SOCIAL_ENGINEERING');
    const hasSuspect  = threats.some(s => s.verdict === 'SUSPICIOUS' || s.verdict === 'THREAT_DETECTED');

    if (hasMalware) { overallVerdict = 'MALWARE CONFIRMED'; overallSeverity = 100; }
    else if (hasPhishing) { overallVerdict = 'PHISHING CONFIRMED'; overallSeverity = 90; }
    else if (hasSuspect)  { overallVerdict = 'SUSPICIOUS'; overallSeverity = 60; }
  }

  return {
    overallVerdict,
    overallSeverity,
    sourcesQueried: sources.length,
    sourcesActive: active.length,
    threatsDetected: threats.length,
    sources: { virusTotal: vt, googleSafeBrowsing: gsb, urlScan: us }
  };
}
