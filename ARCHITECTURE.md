# LinkGuard — Architecture

## System Shape

LinkGuard is designed with an isomorphic architecture: the core parser, heuristic detection rules, and scoring model are implemented as pure, zero-dependency ES modules that execute identically both inside the browser (100% offline client-side) and within a Node.js REST API server.

```
┌─────────────────────────────────────────────────────────────┐
│                 Client (Browser) & Server                   │
│                                                             │
│  Input ──▶ Parser ──▶ Heuristic Engine (10 Checks) ──▶     │
│                            │                                │
│                            ▼                                │
│                      Scoring Model                          │
│                            │                                │
│                            ▼                                │
│                   Result Renderer / API                     │
└─────────────────────────────────────────────────────────────┘
```

## Core Components

### 1. Parser (`parser.js`)
Takes any raw input string and safely decomposes it:
- Handles missing protocols (e.g. `example.com` normalized to `https://example.com` or raw inspection)
- Decodes obfuscated/percent-encoded characters safely
- Extracts protocol, userinfo (`user:pass`), host, port, subdomains chain, registered root domain, TLD, path, search params, and hash
- Computes Shannon entropy across the entire URL and path segments
- Detects non-standard ports (e.g., `:8080`, `:8888`, `:21`)
- Flags parse failures without throwing exceptions

### 2. Heuristic Engine (`heuristics.js`)
Contains 10 independent pure heuristic checks:
1. `checkProtocol`: Flags unencrypted HTTP or abnormal schemes (`data:`, `javascript:`, `ftp:`)
2. `checkIpHost`: Flags IPv4/IPv6 literal hosts (including standard dot-decimal, decimal integer, octal, and hex notation)
3. `checkAtSymbol`: Detects userinfo credential-spoofing trick (`https://trusted.com@evil.com`)
4. `checkPunycodeHomograph`: Flags `xn--` Punycode and mixed-script Cyrillic/Greek homoglyphs
5. `checkSubdomainCount`: Flags excessive subdomain nesting (>= 3 subdomains) used to bury brand names
6. `checkHyphenDensity`: Flags excessive hyphenation in the domain (>= 2 hyphens, e.g. `paypal-security-update-account`)
7. `checkKnownShorteners`: Identifies URL shortener services that hide the final destination
8. `checkSuspiciousTlds`: Identifies high-abuse or free top-level domains (.tk, .ga, .cf, .xyz, .top, .buzz, etc.)
9. `checkBrandImpersonation`: Identifies known brands (`paypal`, `apple`, `google`, `chase`, etc.) appearing in subdomains or path when the root domain does not belong to that brand
10. `checkUrlEntropyAndLength`: Measures abnormal URL length (> 75 chars) and Shannon entropy (> 4.2 bits/char)

Each check returns:
```javascript
{
  id: "brand-impersonation",
  label: "Brand impersonation",
  category: "Identity & Trust",
  passed: false,
  scoreContribution: 35,
  maxWeight: 35,
  explanation: "The brand 'paypal' appears in the subdomain or path, but the actual root domain is 'phishing-site.xyz'.",
  details: { ... }
}
```

### 3. Scoring Model (`scoring.js`)
Aggregates weighted check deductions into a normalized 0–100 risk score:
- **Low Risk (0–29)**: Safe or benign URLs with standard characteristics
- **Medium Risk (30–59)**: Suspicious signals (e.g. shortener or high hyphens) requiring user caution
- **High Risk (60–100)**: Critical phishing indicators (e.g. IP host, brand impersonation, punycode lookalike)

### 4. Resolver (`resolver.js`) [Backend Extension]
- Safe DNS resolution lookup
- Optional unshortening redirect crawler (follows redirects safely up to 3 hops with strict timeouts and local network IP protection against SSRF)

### 5. UI Result Renderer (`app.js` & `style.css`)
- SVG Circular Instrument Dial with animated settling needle
- High-contrast verdict card
- Comprehensive collapsible heuristic breakdown with clear badges and educational explanations
- Component token viewer (Protocol, Subdomain, Domain, TLD, Path)
- Live character entropy bar
- 1-click test suite with real-world examples
- Batch analysis mode
