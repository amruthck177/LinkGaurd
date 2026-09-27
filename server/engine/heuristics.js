/**
 * LinkGuard Heuristic Engine
 * 10 pure, independent detection checks based on phishing URL mechanics.
 */

// Well-known brands frequently targeted in credential harvesting and impersonation
export const TARGET_BRANDS = {
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

// Known URL shorteners that obfuscate the actual destination
export const KNOWN_SHORTENERS = new Set([
  'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd',
  'buff.ly', 'adf.ly', 'bit.do', 'cutt.ly', 'rb.gy', 'shorturl.at',
  's.id', 'qr.ae', 'shorte.st', 'trib.al', 'tiny.cc', 'bl.ink'
]);

// Suspicious / heavily abused or historically free TLDs frequently seen in bulk phishing
export const SUSPICIOUS_TLDS = new Set([
  'tk', 'ml', 'ga', 'cf', 'gq', 'top', 'xyz', 'work', 'click',
  'loan', 'buzz', 'fit', 'surf', 'country', 'stream', 'gdn',
  'date', 'racing', 'win', 'bid', 'vip', 'icu', 'monster', 'rest'
]);

/**
 * Check 1: Protocol (Missing HTTPS or unsafe protocol)
 */
export function checkProtocol(url) {
  const id = 'protocol';
  const label = 'Protocol Security';
  const category = 'Transport';
  const weight = 15;

  if (url.originalProtocol === 'http') {
    return {
      id,
      label,
      category,
      passed: false,
      weight,
      scoreContribution: 15,
      explanation: 'Uses unencrypted HTTP. Data sent over plaintext HTTP can be intercepted or manipulated in transit by attackers.',
      details: { protocol: 'http', secure: false }
    };
  }

  if (url.hadMissingScheme) {
    return {
      id,
      label,
      category,
      passed: false,
      weight,
      scoreContribution: 10,
      explanation: 'No explicit protocol scheme provided (e.g. missing https://). Links without explicit schemes can default to insecure transport.',
      details: { protocol: 'unspecified', secure: false }
    };
  }

  if (url.originalProtocol && url.originalProtocol !== 'https') {
    return {
      id,
      label,
      category,
      passed: false,
      weight,
      scoreContribution: 25,
      explanation: `Unusual URL scheme "${url.originalProtocol}:". Non-web protocols or schemes like "javascript:" or "data:" are often exploited.`,
      details: { protocol: url.originalProtocol, secure: false }
    };
  }

  return {
    id,
    label,
    category,
    passed: true,
    weight,
    scoreContribution: 0,
    explanation: 'Uses HTTPS protocol with standard transport encryption.',
    details: { protocol: 'https', secure: true }
  };
}

/**
 * Check 2: IP-Literal Host
 */
export function checkIpHost(url) {
  const id = 'ip-host';
  const label = 'IP-Literal Host';
  const category = 'Domain & DNS';
  const weight = 35;

  if (url.isIp) {
    return {
      id,
      label,
      category,
      passed: false,
      weight,
      scoreContribution: 35,
      explanation: `Destination is a direct IP address (${url.host}) rather than a registered domain name. Legitimate web services rarely direct users directly to numeric IP addresses.`,
      details: { host: url.host, isIp: true }
    };
  }

  return {
    id,
    label,
    category,
    passed: true,
    weight,
    scoreContribution: 0,
    explanation: 'Host uses a standard domain name rather than an IP literal.',
    details: { host: url.host, isIp: false }
  };
}

/**
 * Check 3: @ Symbol in URL (Userinfo redirect trick)
 */
export function checkAtSymbol(url) {
  const id = 'at-symbol';
  const label = 'Credential / @ Symbol Redirection';
  const category = 'Syntax & Obfuscation';
  const weight = 35;

  if (url.hasAtSymbol) {
    return {
      id,
      label,
      category,
      passed: false,
      weight,
      scoreContribution: 35,
      explanation: 'Contains an "@" symbol in the authority component. Browsers treat everything preceding the "@" as user credentials and route navigation strictly to the host following it.',
      details: { hasAtSymbol: true, host: url.host, username: url.username }
    };
  }

  return {
    id,
    label,
    category,
    passed: true,
    weight,
    scoreContribution: 0,
    explanation: 'No "@" symbol found in the URL authority section.',
    details: { hasAtSymbol: false }
  };
}

/**
 * Check 4: Punycode / Homograph (Lookalike non-Latin domains)
 */
export function checkPunycodeHomograph(url) {
  const id = 'punycode-homograph';
  const label = 'Punycode / Homograph Lookalike';
  const category = 'Visual Deception';
  const weight = 30;

  if (url.isPunycode) {
    return {
      id,
      label,
      category,
      passed: false,
      weight,
      scoreContribution: 30,
      explanation: `Domain contains Punycode prefix "xn--" (${url.host}). Punycode allows attackers to register visual lookalikes using Cyrillic or Greek characters (e.g. Cyrillic "а" spoofing Latin "a").`,
      details: { host: url.host, isPunycode: true }
    };
  }

  if (url.homoglyphs && url.homoglyphs.hasMixedScript) {
    return {
      id,
      label,
      category,
      passed: false,
      weight,
      scoreContribution: 30,
      explanation: `Mixed-script characters detected: contains non-ASCII characters [${url.homoglyphs.nonAsciiChars.join(', ')}] visually mimicking Latin characters.`,
      details: { homoglyphs: url.homoglyphs }
    };
  }

  return {
    id,
    label,
    category,
    passed: true,
    weight,
    scoreContribution: 0,
    explanation: 'No Punycode (xn--) or homoglyph character spoofing detected in host.',
    details: { isPunycode: false, hasHomoglyphs: false }
  };
}

/**
 * Check 5: Subdomain Count (Deeply nested subdomains)
 */
export function checkSubdomainCount(url) {
  const id = 'subdomain-count';
  const label = 'Subdomain Depth';
  const category = 'Domain & DNS';
  const weight = 15;

  // 0-1 subdomains: standard (e.g., www.example.com or example.com)
  // 2 subdomains: mild (e.g., auth.login.example.com)
  // >= 3 subdomains: high suspicion (e.g., paypal.com.account-update.secure.evil.com)
  const count = url.subdomainCount || 0;

  if (count >= 3) {
    return {
      id,
      label,
      category,
      passed: false,
      weight,
      scoreContribution: 15,
      explanation: `Excessive subdomain nesting (${count} subdomains: "${url.subdomainString}"). Attackers frequently chain subdomains to bury the real registered domain off-screen.`,
      details: { count, subdomains: url.subdomains, rootDomain: url.rootDomain }
    };
  }

  if (count === 2) {
    return {
      id,
      label,
      category,
      passed: true,
      weight,
      scoreContribution: 5,
      explanation: `Domain contains 2 subdomains ("${url.subdomainString}"). Common in enterprise microservices, but worth noting.`,
      details: { count, subdomains: url.subdomains, rootDomain: url.rootDomain }
    };
  }

  return {
    id,
    label,
    category,
    passed: true,
    weight,
    scoreContribution: 0,
    explanation: `Normal subdomain structure (${count === 0 ? 'root domain only' : 'standard single prefix'}).`,
    details: { count, subdomains: url.subdomains, rootDomain: url.rootDomain }
  };
}

/**
 * Check 6: Hyphen Density
 */
export function checkHyphenDensity(url) {
  const id = 'hyphen-density';
  const label = 'Hyphen Density in Host';
  const category = 'Visual Deception';
  const weight = 15;

  const hyphenCount = url.hyphenCountInHost || 0;

  if (hyphenCount >= 3) {
    return {
      id,
      label,
      category,
      passed: false,
      weight,
      scoreContribution: 15,
      explanation: `High hyphen density in domain name (${hyphenCount} hyphens: "${url.host}"). Phishing domains frequently string hyphens together to fabricate legitimate-looking titles.`,
      details: { hyphenCount, host: url.host }
    };
  }

  if (hyphenCount === 2) {
    return {
      id,
      label,
      category,
      passed: false,
      weight,
      scoreContribution: 8,
      explanation: `Domain contains multiple hyphens (${hyphenCount}: "${url.host}"). Often used in deceptive domain registrations.`,
      details: { hyphenCount, host: url.host }
    };
  }

  return {
    id,
    label,
    category,
    passed: true,
    weight,
    scoreContribution: 0,
    explanation: `Domain host contains normal hyphen count (${hyphenCount}).`,
    details: { hyphenCount, host: url.host }
  };
}

/**
 * Check 7: Known Shorteners
 */
export function checkKnownShorteners(url) {
  const id = 'known-shorteners';
  const label = 'URL Shortener Service';
  const category = 'Destination Obfuscation';
  const weight = 25;

  const isShortener = KNOWN_SHORTENERS.has(url.host) || KNOWN_SHORTENERS.has(url.rootDomain);

  if (isShortener) {
    return {
      id,
      label,
      category,
      passed: false,
      weight,
      scoreContribution: 25,
      explanation: `URL uses a known shortener service ("${url.host}"). Shorteners completely mask the destination server, preventing inspection prior to clicking.`,
      details: { shortener: url.host, masked: true }
    };
  }

  return {
    id,
    label,
    category,
    passed: true,
    weight,
    scoreContribution: 0,
    explanation: 'URL does not route through a known anonymizing shortener service.',
    details: { shortener: false }
  };
}

/**
 * Check 8: Suspicious TLDs
 */
export function checkSuspiciousTlds(url) {
  const id = 'suspicious-tlds';
  const label = 'Top-Level Domain Reputation';
  const category = 'Domain & DNS';
  const weight = 20;

  const tld = (url.tld || '').toLowerCase();
  const isSuspicious = SUSPICIOUS_TLDS.has(tld);

  if (isSuspicious) {
    return {
      id,
      label,
      category,
      passed: false,
      weight,
      scoreContribution: 20,
      explanation: `Uses top-level domain ".${tld}". This TLD has high historical abuse rates or offers free registrations that are heavily exploited in automated phishing campaigns.`,
      details: { tld, suspicious: true }
    };
  }

  return {
    id,
    label,
    category,
    passed: true,
    weight,
    scoreContribution: 0,
    explanation: `Uses established top-level domain ".${tld || 'unknown'}".`,
    details: { tld, suspicious: false }
  };
}

/**
 * Check 9: Brand Impersonation
 */
export function checkBrandImpersonation(url) {
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

    if (isLegit) {
      // It's the official brand domain, so it's not impersonation
      continue;
    }

    // Check if brand name is embedded in subdomain or host prefix
    if (fullHost.includes(brand)) {
      flaggedBrand = brand;
      contextFound = `in host "${url.host}" while root domain is "${url.rootDomain}"`;
      break;
    }

    // Check if brand is in normalized decoded host (Punycode / homoglyphs spoofing brand)
    if (normalizedLatinHost.includes(brand)) {
      flaggedBrand = brand;
      contextFound = `in homoglyph / Punycode decoded host "${url.decodedHost || url.host}" targeting brand "${brand}"`;
      break;
    }

    // Check if brand name is in path pretending to be a login portal (e.g. /paypal/login or /apple-id)
    if (path.includes(`/${brand}`) || path.includes(`${brand}-login`) || path.includes(`${brand}-verify`)) {
      flaggedBrand = brand;
      contextFound = `in path "${url.pathname}" on third-party domain "${url.rootDomain}"`;
      break;
    }
  }

  if (flaggedBrand) {
    return {
      id,
      label,
      category,
      passed: false,
      weight,
      scoreContribution: 35,
      explanation: `Known brand name "${flaggedBrand}" detected ${contextFound}. Phishing attacks frequently place recognized brand names in subdomains or paths to trick users into trusting a foreign root domain.`,
      details: { brand: flaggedBrand, context: contextFound, rootDomain: url.rootDomain }
    };
  }

  return {
    id,
    label,
    category,
    passed: true,
    weight,
    scoreContribution: 0,
    explanation: 'No known brand impersonation detected across domain, subdomains, or primary path.',
    details: { brandDetected: false }
  };
}

/**
 * Check 10: URL Length and Entropy
 */
export function checkUrlEntropyAndLength(url) {
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
      id,
      label,
      category,
      passed: false,
      weight,
      scoreContribution: 15,
      explanation: `Abnormally long URL (${length} chars) with high Shannon entropy (${entropy} bits/char). High entropy in lengthy paths often indicates encoded malware binaries, tracking payloads, or obfuscated payloads.`,
      details: { length, entropy, pathLength, pathEntropy }
    };
  }

  if (isExcessivelyLong) {
    return {
      id,
      label,
      category,
      passed: false,
      weight,
      scoreContribution: 8,
      explanation: `URL is unusually long (${length} characters). Long URLs are sometimes used to hide the true destination beyond the mobile address bar visible area.`,
      details: { length, entropy }
    };
  }

  if (isHighEntropy && pathLength > 20) {
    return {
      id,
      label,
      category,
      passed: false,
      weight,
      scoreContribution: 8,
      explanation: `Elevated randomness (Shannon entropy: ${entropy} bits/char) in URL path.`,
      details: { length, entropy }
    };
  }

  return {
    id,
    label,
    category,
    passed: true,
    weight,
    scoreContribution: 0,
    explanation: `Standard length (${length} chars) and normal character distribution (entropy: ${entropy} bits/char).`,
    details: { length, entropy }
  };
}

/**
 * Array of all 10 heuristic check functions in execution order
 */
export const ALL_HEURISTICS = [
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

/**
 * Runs all heuristic checks on a parsed URL object.
 * @param {object} parsedUrl
 * @returns {Array<object>}
 */
export function runHeuristics(parsedUrl) {
  return ALL_HEURISTICS.map(checkFn => checkFn(parsedUrl));
}
