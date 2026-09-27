/**
 * LinkGuard Core Parser
 * Robust, safe URL decomposition with defensive tokenization & character analysis.
 */

// Common multi-part TLDs (country-code SLDs)
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

/**
 * Calculates the Shannon Entropy of a string.
 * High entropy indicates randomized, encrypted, or obfuscated characters.
 * @param {string} str
 * @returns {number}
 */
export function calculateShannonEntropy(str) {
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

/**
 * Checks if a string represents an IPv4 address (standard, octal, hex, or decimal).
 * @param {string} host
 * @returns {boolean}
 */
export function isIpAddress(host) {
  if (!host) return false;
  // Clean IPv6 brackets if any
  const cleanHost = host.replace(/^\[|\]$/g, '');

  // Standard IPv4 (0-255.0-255.0-255.0-255)
  const ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
  if (ipv4Regex.test(cleanHost)) return true;

  // Standard IPv6
  const ipv6Regex = /^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^::1$|^([0-9a-fA-F]{1,4}:){1,7}:|^:((:[0-9a-fA-F]{1,4}){1,7}|:)$/;
  if (ipv6Regex.test(cleanHost)) return true;

  // Decimal integer IP (e.g. 2130706433 for 127.0.0.1)
  if (/^\d{8,11}$/.test(cleanHost)) {
    const num = parseInt(cleanHost, 10);
    if (num > 0 && num <= 4294967295) return true;
  }

  // Hexadecimal IP (e.g. 0x7f000001)
  if (/^0x[0-9a-fA-F]{8}$/.test(cleanHost)) return true;

  // Octal/Dotted mixed hex IPv4 representations
  if (/^(0[0-7]+\.|0x[0-9a-fA-F]+\.)+[0-9a-fA-F]+$/i.test(cleanHost)) return true;

  return false;
}

/**
 * Extracts root domain, subdomains, and TLD from hostname
 * @param {string} hostname
 */
export function extractDomainParts(hostname) {
  if (!hostname || isIpAddress(hostname)) {
    return {
      subdomains: [],
      subdomainString: '',
      rootDomain: hostname || '',
      mainDomain: hostname || '',
      tld: ''
    };
  }

  const parts = hostname.toLowerCase().split('.').filter(Boolean);
  if (parts.length === 0) {
    return { subdomains: [], subdomainString: '', rootDomain: '', mainDomain: '', tld: '' };
  }
  if (parts.length === 1) {
    return { subdomains: [], subdomainString: '', rootDomain: parts[0], mainDomain: parts[0], tld: '' };
  }

  // Check for multi-part TLD (e.g., example.co.uk)
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

/**
 * Lightweight RFC 3492 Punycode decoder for Internationalized Domain Names.
 * @param {string} input
 * @returns {string}
 */
export function decodePunycode(input) {
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

// Map common visual homoglyphs (Cyrillic, Greek) to standard Latin equivalents
const HOMOGLYPH_MAP = {
  'а': 'a', 'с': 'c', 'е': 'e', 'і': 'i', 'ј': 'j', 'к': 'k', 'о': 'o', 'р': 'p', 'ѕ': 's', 'у': 'y', 'х': 'x',
  'А': 'a', 'В': 'b', 'С': 'c', 'Е': 'e', 'Н': 'h', 'І': 'i', 'Ј': 'j', 'К': 'k', 'М': 'm', 'О': 'o', 'Р': 'p',
  'Т': 't', 'Х': 'x', 'У': 'y', 'α': 'a', 'ο': 'o', 'ρ': 'p', 'ν': 'v', 'τ': 't'
};

/**
 * Normalizes visual lookalike characters into Latin characters.
 * @param {string} str
 * @returns {string}
 */
export function normalizeHomoglyphs(str) {
  if (!str) return '';
  return str.split('').map(ch => HOMOGLYPH_MAP[ch] || ch).join('').toLowerCase();
}

/**
 * Checks for mixed-script or homoglyph characters
 * Detects Cyrillic, Greek, or other non-Latin characters commonly used to spoof Latin letters.
 * @param {string} str
 */
export function detectHomoglyphs(str) {
  if (!str) return { hasNonAscii: false, nonAsciiChars: [], hasMixedScript: false };

  // Common confusable Unicode ranges: Cyrillic (0400-04FF), Greek (0370-03FF)
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

/**
 * Safely parses any raw user string into a structured LinkGuard URL model.
 * Never throws — returns a parsed object with parseError flag if invalid.
 * @param {string} rawInput
 */
export function parseUrl(rawInput) {
  if (typeof rawInput !== 'string') {
    return { isValid: false, parseError: 'Input must be a string', raw: '' };
  }

  const trimmed = rawInput.trim();
  if (!trimmed) {
    return { isValid: false, parseError: 'URL input is empty', raw: '' };
  }

  let normalized = trimmed;
  let hadMissingScheme = false;

  // Check if protocol is missing
  if (!/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(normalized)) {
    // If it looks like user typed domain or path, assume http/https for parsing
    normalized = 'http://' + normalized;
    hadMissingScheme = true;
  }

  let parsed;
  try {
    parsed = new URL(normalized);
  } catch (err) {
    return {
      isValid: false,
      parseError: `Malformed URL: ${err.message}`,
      raw: trimmed,
      trimmed
    };
  }

  const rawHost = parsed.hostname.toLowerCase();
  const domainParts = extractDomainParts(rawHost);
  const isIp = isIpAddress(rawHost);
  const isPunycode = rawHost.includes('xn--');

  // Decode Punycode and check decoded Unicode characters
  const decodedUnicodeHost = isPunycode ? decodePunycode(rawHost) : rawHost;
  const normalizedLatinHost = normalizeHomoglyphs(decodedUnicodeHost);
  const homoglyphData = detectHomoglyphs(trimmed.includes('xn--') ? decodedUnicodeHost : trimmed);

  // Check for @ symbol trick in the authority / original input
  const rawBeforePath = trimmed.split('/')[2] || trimmed.split('/')[0];
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
