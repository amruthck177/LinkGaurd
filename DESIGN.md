# LinkGuard — Design Specification

## Design Intent

LinkGuard avoids the generic dark-neon "hacker green" cliché. Instead, it is crafted as a high-precision, calm diagnostic instrument with warm editorial typography and restrained, functional color accents.

## Design Tokens

| Token | Value | Role |
|---|---|---|
| `--surface` | `#F6F5F1` | Page background — warm, paper-like, quiet |
| `--surface-panel` | `#FFFFFF` | Card/panel background |
| `--surface-subtle` | `#EDECE6` | Input fields, code chips, hover states |
| `--ink` | `#1B1E1C` | Primary text and headlines |
| `--ink-muted` | `#5B5F5C` | Secondary labels, descriptions, and captions |
| `--line` | `#DCD9D1` | Hairline borders, dividers, subtle borders |
| `--risk-low` | `#2E6B4F` | Low-risk status, passed checks (calm forest green) |
| `--risk-medium` | `#B8823A` | Medium-risk status, cautionary checks (warm amber) |
| `--risk-high` | `#A63D3D` | High-risk status, critical alerts (deep crimson) |

## Typography

- **Display / Verdict**: *Source Serif 4* / *Lora* (serif) — establishes thoughtful authority and clinical assessment.
- **UI / Body**: *IBM Plex Sans* / *Inter* (sans-serif) — clear, high legibility for explanations, controls, and tables.
- **Data / Tokens**: *IBM Plex Mono* (monospace) — used exclusively for raw URLs, domain components, IP addresses, and entropy readings.

## Key UI Components

1. **Top Navigation Bar**: Clean brand mark with status badge and quick toggle between Single Link Inspector, Batch Scanner, and Heuristic Guide.
2. **Hero Input**: Centered, generous input box with clear action button and sample link pills for quick testing.
3. **Verdict Panel**:
   - Circular gauge dial featuring smooth settling animation.
   - Large verdict typography with plain-language diagnostic summary.
   - Component decomposition bar (Protocol, Host, Subdomain, Path, Port).
4. **Heuristic Checklist**:
   - Collapsible cards for each of the 10 checks.
   - Color-coded status icons (`✓` Passed, `⚠` Warning, `✕` Flagged).
   - Plain-English breakdown explaining the mechanics of the attack vector.
5. **Interactive Educational Sandbox**:
   - Allows users to test known phishing techniques (Homograph lookalike, IP literal host, Subdomain burying, Free TLDs, and Obfuscated shorteners).
