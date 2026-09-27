# LinkGuard

A client-side and full-stack phishing and malicious-URL detector. Paste in a link, and LinkGuard runs it through a set of transparent heuristics — returning a calibrated risk score with the exact reasoning behind it.

## Why this exists

Most phishing links don't get caught because people don't know what to look for. LinkGuard makes the "what to look for" explicit: instead of a black-box verdict, it shows every check it ran and why a URL passed or failed each one. It's built to be both an everyday diagnostic tool and an educational instrument.

## What it checks

| Check | What it catches | Severity Weight |
|---|---|---|
| Protocol | Missing HTTPS / plaintext HTTP | 15 pts |
| IP-literal host | `http://192.168.1.1/login` style links bypassing DNS | 35 pts |
| `@` symbol in URL | Browser credential/redirect trick (`https://brand@evil.com`) | 35 pts |
| Punycode / homograph | Lookalike domains using non-Latin characters (`xn--`) | 30 pts |
| Subdomain count | Excessive nesting used to bury the real domain (>= 3 subdomains) | 15 pts |
| Hyphen density | Domains stuffed with hyphens to mimic brand names | 15 pts |
| Known shorteners | bit.ly, tinyurl, etc. — obfuscating the final destination | 25 pts |
| Suspicious TLDs | Free / heavily abused TLDs (.tk, .ml, .ga, .cf, .xyz, etc.) | 20 pts |
| Brand impersonation | Known brand names appearing outside the registered root domain | 35 pts |
| URL length / entropy | Abnormally long or randomized high-entropy payload paths | 15 pts |

Each check contributes to an overall risk score (0–100) categorized into **Low**, **Medium**, or **High**.

## Threat Intelligence Feeds (Optional)

LinkGuard integrates transparent heuristics with external threat intelligence APIs when configured:
- **VirusTotal v3**: Multi-engine antivirus and URL reputation scanning.
- **Google Safe Browsing v4**: Industry-standard database of malicious, phishing, and malware threats.
- **URLScan.io**: Automated sandbox scanning and domain reputation analysis.

> **Security & Privacy Guarantee**: API keys are stored strictly in-memory during server runtime and are never persisted to disk or exposed in client responses (only masked indicators `vt_t••••••••7890` are returned).

## Tech Stack & Architecture

- **Frontend**: Clean Vanilla HTML5, modern CSS3 (forensic dark-terminal UI tokens, custom properties, responsive layout), Vanilla ES6 JavaScript.
- **Backend**: Node.js & Express REST API:
  - `POST /api/analyze`: Comprehensive single URL analysis with optional Threat Intel.
  - `POST /api/batch`: High-throughput multi-URL bulk audit.
  - `POST /api/threat-check`: Dedicated VirusTotal, Safe Browsing, and URLScan scanner.
  - `GET /api/keys` & `POST /api/keys`: Secure in-memory threat intelligence key management.
  - `GET /api/heuristics`: Registry of all 10 diagnostic heuristics and severity weights.
  - `GET /api/samples`: Curated phishing and benign test samples.
- **Dual Execution Engine**: Heuristic engine runs seamlessly both on the server and purely client-side offline (`index.html` can be run standalone without internet or backend).

## Quick Start

### Running Full-Stack Server
```bash
npm install
npm start
```
Then navigate to `http://localhost:3000` in your web browser.

### Configuring API Keys
1. Navigate to the **API KEYS** tab in the top navigation strip.
2. Enter your API keys for VirusTotal, Google Safe Browsing, and/or URLScan.io.
3. Click **SAVE** — keys take effect immediately for all subsequent scans.
4. Toggle the **THREAT INTEL** switch beside the Link Inspector search bar.

### Running Client-Side Only (Offline Mode)
Simply double-click or open `public/index.html` directly in any web browser.

## Running Tests
```bash
npm test
```

## Disclaimer

LinkGuard is a heuristic diagnostic and educational tool, not an absolute guarantee of safety. A "Low risk" result does not guarantee a URL is benign, and a "High risk" result flags high-suspicion patterns common in phishing campaigns.

