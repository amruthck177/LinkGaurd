# LinkGuard — Project Plan

## Problem Statement

Phishing remains the dominant attack vector on the web. Attackers leverage well-known tricks — such as Punycode lookalikes, IP-literal URLs, multi-level subdomain stuffing, and obfuscated shorteners — that are readily detected by heuristic analysis but invisible to people glancing casually at links. LinkGuard provides a completely transparent, educational, and instant link safety inspector that reveals the exact signals of malicious links without relying on proprietary black-box threat intel feeds.

## Objectives & Deliverables

1. **Pure Heuristic Engine**: 10 distinct, verified rules covering protocol, IP hosts, `@` redirection, Punycode/homographs, subdomain depth, hyphen abuse, shorteners, high-abuse TLDs, brand spoofing, and entropy.
2. **Interactive Web Interface**: A warm, calm diagnostic instrument following the LinkGuard Design Spec (`#F6F5F1`, Source Serif 4, IBM Plex Sans, IBM Plex Mono, SVG gauge dial).
3. **Dual Execution Mode**:
   - Single-file client-side capability (can run offline directly in browser without servers).
   - Node.js / Express backend with full REST API (`/api/analyze`, `/api/batch`, `/api/heuristics`, `/api/health`, `/api/unshorten`).
4. **Educational Value**: Clear, plain-English explanations for every passed and failed check so users understand *why* a pattern is suspicious.
5. **Quality Assurance**: Automated unit test suite verifying heuristics against realistic phishing samples and benign URLs.

## Milestones

- [x] Architecture & Engine design
- [x] Core Parser & Shannon entropy calculator
- [x] 10 Heuristic detection modules
- [x] Scoring & Calibration model
- [x] Backend Express REST API & resolvers
- [x] Diagnostic UI with responsive instrument dial & breakdown
- [x] 1-Click sample laboratory & batch inspection
- [x] Unit test suite
