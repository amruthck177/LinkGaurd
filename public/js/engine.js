/**
 * LinkGuard Client-Side Heuristic Engine
 * Self-contained, zero-dependency browser implementation.
 */

(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.LinkGuardEngine = factory();
  }
})(typeof self !== 'undefined' ? self : this, function () {

  const MULTI_PART_TLDS = new Set([
    'co.uk', 'gov.uk', 'ac.uk', 'org.uk',
    'com.au', 'net.au', 'org.au', 'edu.au',
    'co.nz', 'net.nz', 'org.nz',
    'co.jp', 'ne.jp', 'or.jp',
    'com.br', 'gov.br', 'org.br',
    'co.in', 'net.in', 'org.in', 'gen.in',
    'com.cn', 'net.cn', 'gov.cn',
    'com.sg', 'edu.sg', 'gov.sg',
    'com.mx', 'gob.mx',
    'co.za', 'org.za'
  ]);

  const TARGET_BRANDS = {
    paypal: ['paypal.com', 'paypal.me'],
    apple: ['apple.com', 'icloud.com'],
    microsoft: ['microsoft.com', 'live.com', 'office.com', 'outlook.com', 'microsoftonline.com', 'msn.com', 'azure.com'],
    google: ['google.com', 'youtube.com', 'gmail.com', 'google.co.uk', 'google.co.in', 'googleusercontent.com', 'withgoogle.com'],
    amazon: ['amazon.com', 'amazon.co.uk', 'amazon.de', 'amazon.ca', 'amazon.in', 'media-amazon.com', 'primevideo.com'],
    netflix: ['netflix.com'],
    facebook: ['facebook.com', 'fb.com', 'meta.com'],
    instagram: ['instagram.com'],
    whatsapp: ['whatsapp.com'],
    chase: ['chase.com', 'jpmorganchase.com'],
    wellsfargo: ['wellsfargo.com'],
    bankofamerica: ['bankofamerica.com', 'bofa.com'],
    binance: ['binance.com', 'binance.us'],
    coinbase: ['coinbase.com'],
    steam: ['steampowered.com', 'steamcommunity.com'],
    roblox: ['roblox.com'],
    dhl: ['dhl.com'],
    fedex: ['fedex.com'],
    usps: ['usps.com'],
    ups: ['ups.com'],
    dropbox: ['dropbox.com'],
    adobe: ['adobe.com'],
    spotify: ['spotify.com'],
    linkedin: ['linkedin.com'],
    github: ['github.com', 'github.io']
  };

  const KNOWN_SHORTENERS = new Set([
    'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd',
    'buff.ly', 'adf.ly', 'bit.do', 'cutt.ly', 'rb.gy', 'shorturl.at',
    's.id', 'qr.ae', 'shorte.st', 'trib.al', 'tiny.cc', 'bl.ink'
  ]);

  const SUSPICIOUS_TLDS = new Set([
    'tk', 'ml', 'ga', 'cf', 'gq', 'top', 'xyz', 'work', 'click',
    'loan', 'buzz', 'fit', 'surf', 'country', 'stream', 'gdn',
    'date', 'racing', 'win', 'bid', 'vip', 'icu', 'monster', 'rest'
  ]);

  function calculateShannonEntropy(str) {
    if (!str || str.length === 0) return 0;
    const frequencies = {};
    for (let i = 0; i < str.length; i++) {
      const char = str[i];
      frequencies[char] = (frequencies[char] || 0) + 1;
    }
    let entropy = 0;
    const len = str.length;
    for (const char in frequencies) {
      const p = frequencies[char] / len;
      entropy -= p * Math.log2(p);
    }
    return parseFloat(entropy.toFixed(3));
  }

  function isIpAddress(host) {
    if (!host) return false;
    const cleanHost = host.replace(/^\[|\]$/g, '');
    const ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    if (ipv4Regex.test(cleanHost)) return true;
    const ipv6Regex = /^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^::1$|^([0-9a-fA-F]{1,4}:){1,7}:|^:((:[0-9a-fA-F]{1,4}){1,7}|:)$/;
    if (ipv6Regex.test(cleanHost)) return true;
    if (/^\d{8,11}$/.test(cleanHost)) {
      const num = parseInt(cleanHost, 10);
      if (num > 0 && num <= 4294967295) return true;
    }
    if (/^0x[0-9a-fA-F]{8}$/.test(cleanHost)) return true;
    if (/^(0[0-7]+\.|0x[0-9a-fA-F]+\.)+[0-9a-fA-F]+$/i.test(cleanHost)) return true;
    return false;
  }

  function extractDomainParts(hostname) {
    if (!hostname || isIpAddress(hostname)) {
      return { subdomains: [], subdomainString: '', rootDomain: hostname || '', mainDomain: hostname || '', tld: '' };
    }
    const parts = hostname.toLowerCase().split('.').filter(Boolean);
    if (parts.length === 0) return { subdomains: [], subdomainString: '', rootDomain: '', mainDomain: '', tld: '' };
    if (parts.length === 1) return { subdomains: [], subdomainString: '', rootDomain: parts[0], mainDomain: parts[0], tld: '' };

    const lastTwo = parts.slice(-2).join('.');
    let tld = '';
    let rootDomain = '';
    let subdomains = [];
    let mainDomain = '';

    if (MULTI_PART_TLDS.has(lastTwo) && parts.length >= 3) {
      tld = lastTwo;
      mainDomain = parts[parts.length - 3];
      rootDomain = `${mainDomain}.${tld}`;
      subdomains = parts.slice(0, parts.length - 3);
    } else {
      tld = parts[parts.length - 1];
      mainDomain = parts[parts.length - 2];
      rootDomain = `${mainDomain}.${tld}`;
      subdomains = parts.slice(0, parts.length - 2);
    }

    return {
      subdomains,
      subdomainString: subdomains.join('.'),
      rootDomain,
      mainDomain,
      tld
    };
  }

  function decodePunycode(input) {
    if (!input) return '';
    return input.split('.').map(part => {
      if (!part.toLowerCase().startsWith('xn--')) return part;
      try {
        const str = part.slice(4).toLowerCase();
        const base = 36, tmin = 1, tmax = 26, skew = 38, damp = 700, initial_bias = 72;
        let output = [];
        const delim = str.lastIndexOf('-');
        let b = 0;
        if (delim > 0) {
          for (let j = 0; j < delim; ++j) output.push(str.charCodeAt(j));
          b = delim + 1;
        }
        let i = 0, n_val = 128, bias = initial_bias;
        let in_idx = b;
        while (in_idx < str.length) {
          let oldi = i, w = 1, k = base;
          while (true) {
            const c = str.charAt(in_idx++);
            const code = (c >= 'a' && c <= 'z') ? c.charCodeAt(0) - 97 : (c >= '0' && c <= '9') ? c.charCodeAt(0) - 48 + 26 : 36;
            i += code * w;
            const t = k <= bias ? tmin : k >= bias + tmax ? tmax : k - bias;
            if (code < t) break;
            w *= (base - t);
            k += base;
          }
          const out_len = output.length + 1;
          let delta = (i - oldi) / (oldi === 0 ? damp : 2);
          delta += delta / out_len;
          let k2 = 0;
          while (delta > ((base - tmin) * tmax) / 2) {
            delta /= (base - tmin);
            k2 += base;
          }
          bias = Math.floor(k2 + ((base - tmin + 1) * delta) / (delta + skew));
          n_val += Math.floor(i / out_len);
          i %= out_len;
          output.splice(i, 0, n_val);
          i++;
        }
        return String.fromCodePoint(...output);
      } catch (e) {
        return part;
      }
    }).join('.');
  }

  const HOMOGLYPH_MAP = {
    'а': 'a', 'с': 'c', 'е': 'e', 'і': 'i', 'ј': 'j', 'к': 'k', 'о': 'o', 'р': 'p', 'ѕ': 's', 'у': 'y', 'х': 'x',
    'А': 'a', 'В': 'b', 'С': 'c', 'Е': 'e', 'Н': 'h', 'І': 'i', 'Ј': 'j', 'К': 'k', 'М': 'm', 'О': 'o', 'Р': 'p',
    'Т': 't', 'Х': 'x', 'У': 'y', 'α': 'a', 'ο': 'o', 'ρ': 'p', 'ν': 'v', 'τ': 't'
  };

  function normalizeHomoglyphs(str) {
    if (!str) return '';
    return str.split('').map(ch => HOMOGLYPH_MAP[ch] || ch).join('').toLowerCase();
  }

  function detectHomoglyphs(str) {
    if (!str) return { hasNonAscii: false, nonAsciiChars: [], hasMixedScript: false };
    const nonAscii = [];
    let hasLatin = false;
    let hasConfusable = false;

    for (const char of str) {
      const code = char.charCodeAt(0);
      if ((code >= 65 && code <= 90) || (code >= 97 && code <= 122)) {
        hasLatin = true;
      } else if (code > 127) {
        nonAscii.push(char);
        if ((code >= 0x0400 && code <= 0x04ff) || (code >= 0x0370 && code <= 0x03ff)) {
          hasConfusable = true;
        }
      }
    }

    return {
      hasNonAscii: nonAscii.length > 0,
      nonAsciiChars: Array.from(new Set(nonAscii)),
      hasMixedScript: hasLatin && hasConfusable
    };
  }

  function parseUrl(rawInput) {
    if (typeof rawInput !== 'string') {
      return { isValid: false, parseError: 'Input must be a string', raw: '' };
    }
    const trimmed = rawInput.trim();
    if (!trimmed) {
      return { isValid: false, parseError: 'URL input is empty', raw: '' };
    }

    let normalized = trimmed;
    let hadMissingScheme = false;

    if (!/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(normalized)) {
      normalized = 'http://' + normalized;
      hadMissingScheme = true;
    }

    let parsed;
    try {
      parsed = new URL(normalized);
    } catch (err) {
      return { isValid: false, parseError: `Malformed URL: ${err.message}`, raw: trimmed };
    }

    const rawHost = parsed.hostname.toLowerCase();
    const domainParts = extractDomainParts(rawHost);
    const isIp = isIpAddress(rawHost);
    const isPunycode = rawHost.includes('xn--');
    const decodedUnicodeHost = isPunycode ? decodePunycode(rawHost) : rawHost;
    const normalizedLatinHost = normalizeHomoglyphs(decodedUnicodeHost);
    const homoglyphData = detectHomoglyphs(trimmed.includes('xn--') ? decodedUnicodeHost : trimmed);
    const hasAtSymbol = trimmed.includes('@') || parsed.username !== '' || parsed.password !== '';
    const urlEntropy = calculateShannonEntropy(trimmed);
    const pathEntropy = calculateShannonEntropy(parsed.pathname + parsed.search);

    return {
      isValid: true,
      raw: trimmed,
      normalized: parsed.href,
      protocol: hadMissingScheme ? 'missing' : parsed.protocol.replace(':', ''),
      originalProtocol: hadMissingScheme ? null : parsed.protocol.replace(':', ''),
      hadMissingScheme,
      hasHttps: !hadMissingScheme && parsed.protocol === 'https:',
      host: rawHost,
      decodedHost: decodedUnicodeHost,
      normalizedLatinHost,
      port: parsed.port || '',
      pathname: parsed.pathname || '/',
      search: parsed.search || '',
      hash: parsed.hash || '',
      username: parsed.username || '',
      password: parsed.password || '',
      hasAtSymbol,
      isIp,
      isPunycode,
      homoglyphs: homoglyphData,
      subdomains: domainParts.subdomains,
      subdomainString: domainParts.subdomainString,
      subdomainCount: domainParts.subdomains.length,
      rootDomain: domainParts.rootDomain,
      mainDomain: domainParts.mainDomain,
      tld: domainParts.tld,
      hyphenCountInHost: (rawHost.match(/-/g) || []).length,
      length: trimmed.length,
      pathLength: (parsed.pathname + parsed.search).length,
      entropy: urlEntropy,
      pathEntropy
    };
  }

  // 10 Heuristics
  function checkProtocol(url) {
    const id = 'protocol';
    const label = 'Protocol Security';
    const category = 'Transport';
    const weight = 15;

    if (url.originalProtocol === 'http') {
      return {
        id, label, category, passed: false, weight, scoreContribution: 15,
        explanation: 'Uses unencrypted HTTP. Data sent over plaintext HTTP can be intercepted or manipulated in transit by attackers.',
        details: { protocol: 'http', secure: false }
      };
    }
    if (url.hadMissingScheme) {
      return {
        id, label, category, passed: false, weight, scoreContribution: 10,
        explanation: 'No explicit protocol scheme provided (missing https://). Links without explicit schemes can default to insecure transport.',
        details: { protocol: 'unspecified', secure: false }
      };
    }
    if (url.originalProtocol && url.originalProtocol !== 'https') {
      return {
        id, label, category, passed: false, weight, scoreContribution: 25,
        explanation: `Unusual URL scheme "${url.originalProtocol}:". Non-standard schemes or scripts ("javascript:", "data:") are commonly exploited.`,
        details: { protocol: url.originalProtocol, secure: false }
      };
    }
    return {
      id, label, category, passed: true, weight, scoreContribution: 0,
      explanation: 'Uses HTTPS protocol with standard transport encryption.',
      details: { protocol: 'https', secure: true }
    };
  }

  function checkIpHost(url) {
    const id = 'ip-host';
    const label = 'IP-Literal Host';
    const category = 'Domain & DNS';
    const weight = 35;

    if (url.isIp) {
      return {
        id, label, category, passed: false, weight, scoreContribution: 35,
        explanation: `Destination is a direct IP address (${url.host}) rather than a registered domain name. Legitimate web services rarely direct users directly to numeric IP addresses.`,
        details: { host: url.host, isIp: true }
      };
    }
    return {
      id, label, category, passed: true, weight, scoreContribution: 0,
      explanation: 'Host uses a standard registered domain name rather than an IP literal.',
      details: { host: url.host, isIp: false }
    };
  }

  function checkAtSymbol(url) {
    const id = 'at-symbol';
    const label = 'Credential / @ Symbol Redirection';
    const category = 'Syntax & Obfuscation';
    const weight = 35;

    if (url.hasAtSymbol) {
      return {
        id, label, category, passed: false, weight, scoreContribution: 35,
        explanation: 'Contains an "@" symbol in the authority component. Browsers treat everything preceding the "@" as user credentials and route navigation strictly to the host following it.',
        details: { hasAtSymbol: true, host: url.host, username: url.username }
      };
    }
    return {
      id, label, category, passed: true, weight, scoreContribution: 0,
      explanation: 'No "@" symbol found in the URL authority section.',
      details: { hasAtSymbol: false }
    };
  }

  function checkPunycodeHomograph(url) {
    const id = 'punycode-homograph';
    const label = 'Punycode / Homograph Lookalike';
    const category = 'Visual Deception';
    const weight = 30;

    if (url.isPunycode) {
      return {
        id, label, category, passed: false, weight, scoreContribution: 30,
        explanation: `Domain contains Punycode prefix "xn--" (${url.host}). Punycode allows attackers to register visual lookalikes using Cyrillic or Greek characters (e.g. Cyrillic "а" spoofing Latin "a").`,
        details: { host: url.host, isPunycode: true }
      };
    }
    if (url.homoglyphs && url.homoglyphs.hasMixedScript) {
      return {
        id, label, category, passed: false, weight, scoreContribution: 30,
        explanation: `Mixed-script characters detected: contains non-ASCII characters [${url.homoglyphs.nonAsciiChars.join(', ')}] visually mimicking Latin characters.`,
        details: { homoglyphs: url.homoglyphs }
      };
    }
    return {
      id, label, category, passed: true, weight, scoreContribution: 0,
      explanation: 'No Punycode (xn--) or homoglyph character spoofing detected in host.',
      details: { isPunycode: false, hasHomoglyphs: false }
    };
  }

  function checkSubdomainCount(url) {
    const id = 'subdomain-count';
    const label = 'Subdomain Depth';
    const category = 'Domain & DNS';
    const weight = 15;
    const count = url.subdomainCount || 0;

    if (count >= 3) {
      return {
        id, label, category, passed: false, weight, scoreContribution: 15,
        explanation: `Excessive subdomain nesting (${count} subdomains: "${url.subdomainString}"). Attackers frequently chain subdomains to bury the real registered domain off-screen.`,
        details: { count, subdomains: url.subdomains, rootDomain: url.rootDomain }
      };
    }
    if (count === 2) {
      return {
        id, label, category, passed: true, weight, scoreContribution: 5,
        explanation: `Domain contains 2 subdomains ("${url.subdomainString}"). Common in enterprise microservices, but worth noting.`,
        details: { count, subdomains: url.subdomains, rootDomain: url.rootDomain }
      };
    }
    return {
      id, label, category, passed: true, weight, scoreContribution: 0,
      explanation: `Normal subdomain structure (${count === 0 ? 'root domain only' : 'standard single prefix'}).`,
      details: { count, subdomains: url.subdomains, rootDomain: url.rootDomain }
    };
  }

  function checkHyphenDensity(url) {
    const id = 'hyphen-density';
    const label = 'Hyphen Density in Host';
    const category = 'Visual Deception';
    const weight = 15;
    const hyphenCount = url.hyphenCountInHost || 0;

    if (hyphenCount >= 3) {
      return {
        id, label, category, passed: false, weight, scoreContribution: 15,
        explanation: `High hyphen density in domain name (${hyphenCount} hyphens: "${url.host}"). Phishing domains frequently string hyphens together to fabricate legitimate-looking titles.`,
        details: { hyphenCount, host: url.host }
      };
    }
    if (hyphenCount === 2) {
      return {
        id, label, category, passed: false, weight, scoreContribution: 8,
        explanation: `Domain contains multiple hyphens (${hyphenCount}: "${url.host}"). Often used in deceptive domain registrations.`,
        details: { hyphenCount, host: url.host }
      };
    }
    return {
      id, label, category, passed: true, weight, scoreContribution: 0,
      explanation: `Domain host contains normal hyphen count (${hyphenCount}).`,
      details: { hyphenCount, host: url.host }
    };
  }

  function checkKnownShorteners(url) {
    const id = 'known-shorteners';
    const label = 'URL Shortener Service';
    const category = 'Destination Obfuscation';
    const weight = 25;
    const isShortener = KNOWN_SHORTENERS.has(url.host) || KNOWN_SHORTENERS.has(url.rootDomain);

    if (isShortener) {
      return {
        id, label, category, passed: false, weight, scoreContribution: 25,
        explanation: `URL uses a known shortener service ("${url.host}"). Shorteners completely mask the destination server, preventing inspection prior to clicking.`,
        details: { shortener: url.host, masked: true }
      };
    }
    return {
      id, label, category, passed: true, weight, scoreContribution: 0,
      explanation: 'URL does not route through a known anonymizing shortener service.',
      details: { shortener: false }
    };
  }

  function checkSuspiciousTlds(url) {
    const id = 'suspicious-tlds';
    const label = 'Top-Level Domain Reputation';
    const category = 'Domain & DNS';
    const weight = 20;
    const tld = (url.tld || '').toLowerCase();
    const isSuspicious = SUSPICIOUS_TLDS.has(tld);

    if (isSuspicious) {
      return {
        id, label, category, passed: false, weight, scoreContribution: 20,
        explanation: `Uses top-level domain ".${tld}". This TLD has high historical abuse rates or offers free registrations that are heavily exploited in automated phishing campaigns.`,
        details: { tld, suspicious: true }
      };
    }
    return {
      id, label, category, passed: true, weight, scoreContribution: 0,
      explanation: `Uses established top-level domain ".${tld || 'unknown'}".`,
      details: { tld, suspicious: false }
    };
  }

  function checkBrandImpersonation(url) {
    const id = 'brand-impersonation';
    const label = 'Brand Impersonation';
    const category = 'Identity & Trust';
    const weight = 35;

    const fullHost = (url.host || '').toLowerCase();
    const normalizedLatinHost = (url.normalizedLatinHost || fullHost).toLowerCase();
    const rootDomain = (url.rootDomain || '').toLowerCase();
    const path = (url.pathname || '').toLowerCase();

    let flaggedBrand = null;
    let contextFound = null;

    for (const [brand, legitimateDomains] of Object.entries(TARGET_BRANDS)) {
      const isLegit = legitimateDomains.some(legit => rootDomain === legit || rootDomain.endsWith('.' + legit));
      if (isLegit) continue;

      if (fullHost.includes(brand)) {
        flaggedBrand = brand;
        contextFound = `in host "${url.host}" while root domain is "${url.rootDomain}"`;
        break;
      }
      if (normalizedLatinHost.includes(brand)) {
        flaggedBrand = brand;
        contextFound = `in homoglyph / Punycode decoded host "${url.decodedHost || url.host}" targeting brand "${brand}"`;
        break;
      }
      if (path.includes(`/${brand}`) || path.includes(`${brand}-login`) || path.includes(`${brand}-verify`)) {
        flaggedBrand = brand;
        contextFound = `in path "${url.pathname}" on third-party domain "${url.rootDomain}"`;
        break;
      }
    }

    if (flaggedBrand) {
      return {
        id, label, category, passed: false, weight, scoreContribution: 35,
        explanation: `Known brand name "${flaggedBrand}" detected ${contextFound}. Phishing attacks frequently place recognized brand names in subdomains or paths to trick users into trusting a foreign root domain.`,
        details: { brand: flaggedBrand, context: contextFound, rootDomain: url.rootDomain }
      };
    }

    return {
      id, label, category, passed: true, weight, scoreContribution: 0,
      explanation: 'No known brand impersonation detected across domain, subdomains, or primary path.',
      details: { brandDetected: false }
    };
  }

  function checkUrlEntropyAndLength(url) {
    const id = 'length-entropy';
    const label = 'URL Length & Character Entropy';
    const category = 'Syntax & Obfuscation';
    const weight = 15;
    const length = url.length || 0;
    const pathLength = url.pathLength || 0;
    const entropy = url.entropy || 0;
    const pathEntropy = url.pathEntropy || 0;

    const isExcessivelyLong = length > 120 || pathLength > 90;
    const isHighEntropy = entropy > 4.5 || (pathLength > 25 && pathEntropy > 4.4);

    if (isExcessivelyLong && isHighEntropy) {
      return {
        id, label, category, passed: false, weight, scoreContribution: 15,
        explanation: `Abnormally long URL (${length} chars) with high Shannon entropy (${entropy} bits/char). High entropy in lengthy paths often indicates encoded malware binaries, tracking payloads, or obfuscated payloads.`,
        details: { length, entropy, pathLength, pathEntropy }
      };
    }
    if (isExcessivelyLong) {
      return {
        id, label, category, passed: false, weight, scoreContribution: 8,
        explanation: `URL is unusually long (${length} characters). Long URLs are sometimes used to hide the true destination beyond the mobile address bar visible area.`,
        details: { length, entropy }
      };
    }
    if (isHighEntropy && pathLength > 20) {
      return {
        id, label, category, passed: false, weight, scoreContribution: 8,
        explanation: `Elevated randomness (Shannon entropy: ${entropy} bits/char) in URL path.`,
        details: { length, entropy }
      };
    }
    return {
      id, label, category, passed: true, weight, scoreContribution: 0,
      explanation: `Standard length (${length} chars) and normal character distribution (entropy: ${entropy} bits/char).`,
      details: { length, entropy }
    };
  }

  const ALL_HEURISTICS = [
    checkProtocol,
    checkIpHost,
    checkAtSymbol,
    checkPunycodeHomograph,
    checkSubdomainCount,
    checkHyphenDensity,
    checkKnownShorteners,
    checkSuspiciousTlds,
    checkBrandImpersonation,
    checkUrlEntropyAndLength
  ];

  function runHeuristics(parsedUrl) {
    return ALL_HEURISTICS.map(fn => fn(parsedUrl));
  }

  function calculateScore(checkResults) {
    let rawScore = 0;
    let passedCount = 0;
    let failedCount = 0;

    for (const check of checkResults) {
      if (check.passed && check.scoreContribution === 0) {
        passedCount++;
      } else {
        failedCount++;
        rawScore += (check.scoreContribution || 0);
      }
    }

    const score = Math.min(100, Math.max(0, Math.round(rawScore)));
    let verdict = 'LOW RISK';
    let riskKey = 'low';
    let badge = 'Passed Analysis';
    let color = '#2E6B4F';
    let bgTint = 'rgba(46, 107, 79, 0.08)';
    let summary = 'No high-risk phishing indicators detected. The URL conforms to standard legitimate domain patterns.';

    if (score >= 55) {
      verdict = 'HIGH RISK';
      riskKey = 'high';
      badge = 'Critical Phishing Indicators';
      color = '#A63D3D';
      bgTint = 'rgba(166, 61, 61, 0.10)';
      summary = 'Severe phishing indicators identified. Strong likelihood of credential theft, brand spoofing, or deceptive redirection.';
    } else if (score >= 25) {
      verdict = 'MEDIUM RISK';
      riskKey = 'medium';
      badge = 'Caution Recommended';
      color = '#B8823A';
      bgTint = 'rgba(184, 130, 58, 0.10)';
      summary = 'Suspicious attributes detected. Exercise heightened vigilance and verify authenticity before entering credentials.';
    }

    return {
      score,
      verdict,
      riskKey,
      badge,
      color,
      bgTint,
      summary,
      totalChecks: checkResults.length,
      passedCount,
      failedCount,
      checks: checkResults
    };
  }

  function analyze(rawUrl) {
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
    const checks = runHeuristics(parsed);
    const scoreData = calculateScore(checks);
    return {
      isValid: true,
      url: parsed,
      ...scoreData,
      analyzedAt: new Date().toISOString()
    };
  }

  return {
    parseUrl,
    runHeuristics,
    calculateScore,
    calculateShannonEntropy,
    isIpAddress,
    analyze,
    TARGET_BRANDS,
    KNOWN_SHORTENERS,
    SUSPICIOUS_TLDS,
    ALL_HEURISTICS
  };
});
