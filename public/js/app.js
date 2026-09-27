/**
 * LinkGuard — Forensic Terminal Application Controller
 * Stitch Design: Tactical SOC Workstation · Forensic Tactical Terminal
 * Drives: verdict cockpit, micro-meter, anatomy panel, check-list, batch table
 */

document.addEventListener('DOMContentLoaded', () => {

  /* ── DOM Refs ────────────────────────────────────────────────────── */
  const urlInput      = document.getElementById('urlInput');
  const analyzeBtn    = document.getElementById('analyzeBtn');
  const clearBtn      = document.getElementById('clearBtn');
  const heroSection   = document.getElementById('heroSection');
  const resultsPanel  = document.getElementById('resultsPanel');
  const statusDot     = document.getElementById('statusDot');
  const statusLabel   = document.getElementById('statusLabel');
  const footerEngine  = document.getElementById('footerEngine');

  // Gauge
  const gaugeFill     = document.getElementById('gaugeFill');
  const gaugeNumber   = document.getElementById('gaugeNumber');
  const gaugeLabel    = document.getElementById('gaugeLabel');
  const microMeter    = document.getElementById('microMeter');

  // Verdict
  const verdictCockpit  = document.getElementById('verdictCockpit');
  const verdictBadge    = document.getElementById('verdictBadge');
  const verdictPasses   = document.getElementById('verdictPasses');
  const verdictHeadline = document.getElementById('verdictHeadline');
  const verdictSummary  = document.getElementById('verdictSummary');

  // Case Bar
  const caseBar     = document.getElementById('caseBar');
  const caseFqdn    = document.getElementById('caseFqdn');
  const caseScore   = document.getElementById('caseScore');
  const casePip     = document.getElementById('casePip');
  const casePuny    = document.getElementById('casePunyChip');
  const caseRuntime = document.getElementById('caseRuntime');
  const runtimeChip = document.getElementById('runtimeChip');
  const threatChip  = document.getElementById('threatCountChip');
  const threatLabel = document.getElementById('threatCountLabel');

  // Anatomy
  const anatomyUrl    = document.getElementById('anatomyUrl');
  const anatomyEntropy= document.getElementById('anatomyEntropy');
  const tkProtocol    = document.getElementById('tkProtocol');
  const tkSubdomains  = document.getElementById('tkSubdomains');
  const tkRootDomain  = document.getElementById('tkRootDomain');
  const tkTld         = document.getElementById('tkTld');
  const tkPath        = document.getElementById('tkPath');
  const tkEntropy     = document.getElementById('tkEntropy');

  // Checklist
  const checkList = document.getElementById('checkList');

  // Nav
  const navTabs      = document.querySelectorAll('.nav-tab');
  const viewSections = document.querySelectorAll('.view-section');

  // Batch
  const batchInput   = document.getElementById('batchInput');
  const runBatchBtn  = document.getElementById('runBatchBtn');
  const batchResults = document.getElementById('batchResults');
  const batchTbody   = document.getElementById('batchTbody');
  const batchSummary = document.getElementById('batchSummary');

  // Threat Intel
  const tiToggle      = document.getElementById('tiToggle');
  const tiPanel       = document.getElementById('tiPanel');
  const tiSourcesGrid = document.getElementById('tiSourcesGrid');
  const tiOverallChip = document.getElementById('tiOverallChip');

  let isBackendConnected = false;

  /* ── Stitch Color Tokens (Forensic Tactical Terminal) ─────────── */
  const COLOR = {
    safe:  { stroke: '#00E5A3', text: '#00E5A3', bg: 'rgba(0,229,163,0.08)',  border: 'rgba(0,229,163,0.40)' },
    warn:  { stroke: '#FFB020', text: '#FFB020', bg: 'rgba(255,176,32,0.10)', border: 'rgba(255,176,32,0.35)' },
    crit:  { stroke: '#FF3B30', text: '#FF3B30', bg: 'rgba(255,59,48,0.15)',  border: 'rgba(255,59,48,0.35)'  },
  };

  function riskKey(score) {
    return score >= 55 ? 'crit' : score >= 25 ? 'warn' : 'safe';
  }

  /* ── Backend Health Probe ─────────────────────────────────────── */
  async function probeBackend() {
    try {
      const res = await fetch('/api/health', { signal: AbortSignal.timeout(1500) });
      if (res.ok) {
        const data = await res.json();
        isBackendConnected = true;
        statusLabel.textContent = `API CONNECTED (v${data.version || '1.0'})`;
        if (footerEngine) footerEngine.textContent = `ENGINE: SERVER v${data.version || '1.0'}`;
        return;
      }
    } catch (_) { /* offline */ }
    isBackendConnected = false;
    statusLabel.textContent = 'OFFLINE ENGINE ACTIVE';
    if (footerEngine) footerEngine.textContent = 'ENGINE: CLIENT-SIDE';
  }
  probeBackend();

  /* ── Navigation ──────────────────────────────────────────────── */
  navTabs.forEach(tab => {
    tab.addEventListener('click', () => {
      navTabs.forEach(t => t.classList.remove('active'));
      viewSections.forEach(s => s.classList.remove('active-view'));
      tab.classList.add('active');
      const sec = document.getElementById(tab.dataset.target);
      if (sec) sec.classList.add('active-view');
    });
  });

  /* ── Input Helpers ───────────────────────────────────────────── */
  urlInput.addEventListener('input', () => {
    clearBtn.style.display = urlInput.value.trim() ? 'flex' : 'none';
  });

  clearBtn.addEventListener('click', () => {
    urlInput.value = '';
    clearBtn.style.display = 'none';
    urlInput.focus();
  });

  urlInput.addEventListener('keydown', e => {
    if (e.key === 'Enter') runAnalysis();
  });

  analyzeBtn.addEventListener('click', () => runAnalysis());

  /* ── Sample Tag Clicks ───────────────────────────────────────── */
  document.querySelectorAll('.sample-tag').forEach(tag => {
    tag.addEventListener('click', () => {
      const url = tag.dataset.url;
      if (url) {
        urlInput.value = url;
        clearBtn.style.display = 'flex';
        document.querySelector('[data-target="viewInspector"]').click();
        runAnalysis();
      }
    });
  });

  /* ── Main Analysis ───────────────────────────────────────────── */
  async function runAnalysis() {
    const raw = urlInput.value.trim();
    if (!raw) { urlInput.focus(); return; }

    const t0 = performance.now();
    analyzeBtn.disabled = true;
    analyzeBtn.innerHTML = `
      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" class="spin">
        <circle cx="12" cy="12" r="10" stroke-dasharray="32" stroke-linecap="round"/>
      </svg>
      SCANNING…`;

    try {
      let result;

      if (isBackendConnected) {
        try {
          const useTi = tiToggle && tiToggle.checked;
          const res = await fetch('/api/analyze', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url: raw, resolveDns: true, unshorten: true, threatIntel: useTi })
          });
          if (res.ok) result = await res.json();
        } catch (_) { /* fallthrough */ }
      }

      if (!result && window.LinkGuardEngine) {
        result = window.LinkGuardEngine.analyze(raw);
      }

      if (result) {
        const elapsed = Math.round(performance.now() - t0);
        renderResults(result, elapsed);
        // If threat intel data came back with the analysis, render it
        if (result.threatIntel && !result.threatIntel.noKeysConfigured) {
          renderThreatIntel(result.threatIntel);
        } else if (tiToggle && tiToggle.checked && result.threatIntel?.noKeysConfigured) {
          // Show prompt to configure keys
          if (tiPanel) {
            tiPanel.style.display = 'block';
            tiSourcesGrid.innerHTML = `<div class="ti-source-card" style="grid-column:1/-1">
              <div class="guide-body" style="color:var(--secondary);">⚠ No API keys configured. Go to <strong>API KEYS</strong> tab to add VirusTotal, Google Safe Browsing, or URLScan.io keys.</div>
            </div>`;
            if (tiOverallChip) { tiOverallChip.textContent = 'NO KEYS'; tiOverallChip.className = 'sys-chip warn'; }
          }
        }
      } else {
        alert('Unable to analyze URL. Check input and try again.');
      }
    } catch (err) {
      console.error('Analysis error:', err);
      alert('Heuristic engine error: ' + err.message);
    } finally {
      analyzeBtn.disabled = false;
      analyzeBtn.innerHTML = `
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
          <circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>
        </svg>
        INSPECT`;
    }
  }

  /* ── Render Results ──────────────────────────────────────────── */
  function renderResults(res, elapsed) {
    heroSection.classList.add('compact');
    resultsPanel.style.display = 'block';

    const score = res.score || 0;
    const key   = riskKey(score);
    const col   = COLOR[key];

    // ── Case Bar
    caseBar.style.display = 'flex';
    caseFqdn.textContent = res.raw || '—';
    caseScore.textContent = `SCORE: ${score}/100 · ${key.toUpperCase()}`;
    casePip.style.background = col.stroke;
    casePip.style.boxShadow  = `0 0 6px ${col.stroke}`;

    // Punycode chip
    const hasPuny = (res.checks || []).some(c => c.id === 'punycode' && !c.passed);
    casePuny.style.display = hasPuny ? 'inline-flex' : 'none';

    // Runtime chip
    if (elapsed !== undefined) {
      runtimeChip.style.display = 'flex';
      runtimeChip.textContent = `${elapsed}ms`;
      caseRuntime.textContent = `${elapsed}ms`;
    }

    // Threat count chip
    const flaggedCount = res.failedCount || 0;
    if (flaggedCount > 0) {
      threatChip.style.display = 'flex';
      threatLabel.textContent = `THREAT ${score} CRITICAL`;
    } else {
      threatChip.style.display = 'none';
    }

    // ── Gauge SVG (circumference = 2π × 54 ≈ 339)
    const C = 339;
    const offset = C - (score / 100) * C;
    gaugeFill.style.stroke = col.stroke;
    gaugeFill.style.strokeDashoffset = offset;
    gaugeFill.style.filter = `drop-shadow(0 0 6px ${col.stroke})`;

    // Number roll-up
    animateNumber(gaugeNumber, score, 700);

    // Gauge label
    const labelMap = { safe: 'LOW RISK', warn: 'MEDIUM RISK', crit: 'HIGH RISK' };
    gaugeLabel.textContent = labelMap[key];
    gaugeLabel.style.color = col.stroke;

    // Micro-meter bar (12 segments)
    buildMicroMeter(score);

    // ── Verdict cockpit accent bar
    verdictCockpit.style.setProperty('--vc-accent', col.stroke);

    // Verdict badge
    verdictBadge.textContent = res.badge || res.verdict || key.toUpperCase();
    verdictBadge.style.color         = col.text;
    verdictBadge.style.borderColor   = col.border;
    verdictBadge.style.background    = col.bg;

    verdictPasses.textContent = `${res.passedCount || 0} PASSED · ${res.failedCount || 0} FLAGGED`;
    verdictHeadline.textContent = res.verdict || '—';
    verdictSummary.textContent  = res.summary  || '';

    // ── URL Anatomy
    const u = res.url || {};
    anatomyUrl.textContent = res.raw || u.raw || '—';
    const entropyVal = u.entropy ? `ENTROPY: ${u.entropy} bits/char${u.entropy > 4.2 ? ' ⚠' : ''}` : 'ENTROPY: NORMAL';
    anatomyEntropy.textContent = entropyVal;
    anatomyEntropy.style.color = u.entropy > 4.2 ? 'var(--secondary)' : 'var(--text-muted)';

    tkProtocol.textContent   = (u.hasHttps ? 'https://' : 'http://') + (u.hasHttps ? '[TLS OK]' : '[PLAIN ⚠]');
    tkProtocol.style.color   = u.hasHttps ? 'var(--primary)' : 'var(--hazard)';
    tkSubdomains.textContent = u.subdomainString || '(none)';
    tkRootDomain.textContent = u.rootDomain || u.host || '—';
    tkTld.textContent        = u.tld ? `.${u.tld}` : '(none)';
    tkPath.textContent       = (u.pathname || '/') + (u.search || '');
    tkEntropy.textContent    = u.entropy ? `${u.entropy} b/c` : 'Normal';
    tkEntropy.style.color    = u.entropy > 4.2 ? 'var(--secondary)' : '';

    // ── Checklist
    buildCheckList(res.checks || []);

    // Scroll
    verdictCockpit.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  }

  /* ── Micro-Meter Bar (12 segments) ──────────────────────────── */
  function buildMicroMeter(score) {
    microMeter.innerHTML = '';
    const SEGS = 12;
    const litCount = Math.round((score / 100) * SEGS);
    for (let i = 0; i < SEGS; i++) {
      const seg = document.createElement('div');
      seg.className = 'meter-seg';
      if (i < litCount) {
        const pct = i / SEGS;
        seg.classList.add(pct < 0.45 ? 'lit-green' : pct < 0.75 ? 'lit-amber' : 'lit-red');
      }
      microMeter.appendChild(seg);
    }
  }

  /* ── Animated Number Counter ────────────────────────────────── */
  function animateNumber(el, target, duration) {
    const start = performance.now();
    (function step(now) {
      const p = Math.min((now - start) / duration, 1);
      el.textContent = Math.round((1 - Math.pow(1 - p, 3)) * target);
      if (p < 1) requestAnimationFrame(step);
    })(performance.now());
  }

  /* ── Check List Renderer ─────────────────────────────────────── */
  function buildCheckList(checks) {
    checkList.innerHTML = '';

    checks.forEach(check => {
      const isFail = !check.passed;
      const isWarn = check.passed && (check.scoreContribution || 0) > 0;
      const st = isFail ? 'failed' : isWarn ? 'warning' : 'passed';
      const icon = isFail ? '✕' : '✓';
      const impactText = isFail
        ? `FLAGGED (+${check.scoreContribution} pts)`
        : (isWarn ? `CAUTION (+${check.scoreContribution} pts)` : 'PASS (+0)');

      const row = document.createElement('div');
      row.className = `check-row ${st}${isFail ? ' open' : ''}`;

      row.innerHTML = `
        <div class="check-summary" tabindex="0" role="button" aria-expanded="${isFail}">
          <div class="check-icon ${st}">${icon}</div>
          <div class="check-labels">
            <div class="check-name">${esc(check.label)}</div>
            <div class="check-cat">${esc(check.category || 'Heuristic')}</div>
          </div>
          <div class="check-right">
            <span class="impact-tag ${st}">${impactText}</span>
            <svg class="chevron" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
              <polyline points="6 9 12 15 18 9"/>
            </svg>
          </div>
        </div>
        <div class="check-detail">
          <div class="detail-text">${esc(check.explanation)}</div>
          ${renderEvidence(check.details)}
        </div>
      `;

      const summary = row.querySelector('.check-summary');
      summary.addEventListener('click', () => {
        const open = row.classList.toggle('open');
        summary.setAttribute('aria-expanded', open);
      });
      summary.addEventListener('keydown', e => {
        if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); summary.click(); }
      });

      checkList.appendChild(row);
    });
  }

  function renderEvidence(details) {
    if (!details || !Object.keys(details).length) return '';
    const pairs = Object.entries(details)
      .map(([k, v]) => `<span class="kv-key">${esc(k)}</span><span class="kv-sep">:</span><span class="kv-val">${esc(typeof v === 'object' ? JSON.stringify(v) : String(v))}</span>`)
      .join('  ·  ');
    return `<div class="evidence-block">${pairs}</div>`;
  }

  function esc(str) {
    if (str == null) return '';
    return String(str)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;')
      .replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#039;');
  }

  /* ── Threat Intelligence Panel Renderer ─────────────────────── */
  function renderThreatIntel(ti) {
    if (!tiPanel || !tiSourcesGrid) return;
    tiPanel.style.display = 'block';
    tiSourcesGrid.innerHTML = '';

    const overallKey = (ti.overallVerdict || 'CLEAN').toLowerCase();
    const overallClass = overallKey.includes('malware') || overallKey.includes('malicious') ? 'crit'
                       : overallKey.includes('phish') || overallKey.includes('suspicious') ? 'warn'
                       : 'active';

    if (tiOverallChip) {
      tiOverallChip.textContent = ti.overallVerdict || 'CLEAN';
      tiOverallChip.className = `sys-chip ${overallClass}`;
    }

    const sources = ti.sources || {};
    const defs = [
      { key: 'virusTotal',         label: 'VIRUSTOTAL',          accentColor: '#4285f4' },
      { key: 'googleSafeBrowsing', label: 'GOOGLE SAFE BROWSING', accentColor: '#34a853' },
      { key: 'urlScan',            label: 'URLSCAN.IO',           accentColor: '#a855f7' }
    ];

    defs.forEach(({ key, label, accentColor }) => {
      const s = sources[key];
      if (!s) return;
      tiSourcesGrid.appendChild(buildSourceCard(label, s, accentColor));
    });
  }

  function buildSourceCard(label, s, accent) {
    const card = document.createElement('div');

    const vraw = (s.verdict || 'SKIPPED').toUpperCase();
    const vclass = s.skipped ? 'skipped'
      : (vraw.includes('MALWARE') || vraw.includes('MALICIOUS')) ? 'malicious'
      : (vraw.includes('PHISH') || vraw.includes('SUSPICIOUS') || vraw.includes('THREAT')) ? 'suspicious'
      : vraw === 'CLEAN' ? 'clean'
      : 'pending';

    card.className = `ti-source-card ${s.skipped ? '' : vclass}`;

    let rows = '';

    if (s.skipped) {
      rows = `<div class="guide-body" style="color:var(--text-muted);">No key configured. Add one in the <strong>API KEYS</strong> tab.</div>`;
    } else if (s.error) {
      rows = `<div class="guide-body" style="color:var(--hazard);">Error: ${esc(s.message || 'Unknown error')}</div>`;
    } else {
      // VirusTotal fields
      if (s.detectionRate !== undefined) {
        const isBad = s.malicious > 0;
        rows += `<div class="ti-detail-row"><span class="ti-det-key">DETECTION</span><span class="ti-det-val ${isBad ? 'danger' : 'ok'}">${esc(s.detectionRate)} engines</span></div>`;
      }
      if (s.reputation !== undefined && s.reputation !== null) {
        rows += `<div class="ti-detail-row"><span class="ti-det-key">REPUTATION</span><span class="ti-det-val ${s.reputation < 0 ? 'danger' : 'ok'}">${s.reputation}</span></div>`;
      }
      // Google Safe Browsing fields
      if (Array.isArray(s.threats) && s.threats.length > 0) {
        rows += `<div class="ti-detail-row"><span class="ti-det-key">THREAT TYPES</span><span class="ti-det-val danger">${esc(s.threats.map(t => t.type).join(', '))}</span></div>`;
      }
      if (s.matchCount !== undefined) {
        rows += `<div class="ti-detail-row"><span class="ti-det-key">MATCHES</span><span class="ti-det-val ${s.matchCount > 0 ? 'danger' : 'ok'}">${s.matchCount}</span></div>`;
      }
      // URLScan fields
      if (s.score !== undefined) {
        rows += `<div class="ti-detail-row"><span class="ti-det-key">RISK SCORE</span><span class="ti-det-val ${s.score > 50 ? 'danger' : 'ok'}">${s.score}</span></div>`;
      }
      if (s.ip) rows += `<div class="ti-detail-row"><span class="ti-det-key">RESOLVED IP</span><span class="ti-det-val">${esc(s.ip)}</span></div>`;
      if (s.country) rows += `<div class="ti-detail-row"><span class="ti-det-key">GEO</span><span class="ti-det-val">${esc(s.country)}</span></div>`;
      if (s.redirectedTo) rows += `<div class="ti-detail-row"><span class="ti-det-key">REDIRECTS TO</span><span class="ti-det-val warn" style="word-break:break-all;max-width:150px;overflow:hidden;text-overflow:ellipsis;">${esc(s.redirectedTo)}</span></div>`;
      if (s.note) rows += `<div class="guide-body" style="color:var(--text-muted);font-size:9px;margin-top:3px;">${esc(s.note)}</div>`;
    }

    card.innerHTML = `
      <div class="ti-card-head">
        <span class="ti-source-name" style="color:${accent}">${esc(label)}</span>
        <span class="ti-verdict-tag ${vclass}">${esc(vraw)}</span>
      </div>
      ${rows}
    `;

    // Append screenshot thumbnail if available
    if (s.screenshotUrl) {
      const img = document.createElement('img');
      img.src = s.screenshotUrl;
      img.alt = `${label} screenshot`;
      img.className = 'ti-screenshot-thumb';
      img.onerror = () => img.remove();
      card.appendChild(img);
    }

    return card;
  }

  /* ── Batch Scanner ───────────────────────────────────────────── */
  if (runBatchBtn) {
    runBatchBtn.addEventListener('click', async () => {
      const lines = (batchInput.value || '').split('\n').map(l => l.trim()).filter(Boolean).slice(0, 50);
      if (!lines.length) { alert('Enter at least one URL.'); return; }

      runBatchBtn.disabled = true;
      runBatchBtn.textContent = `SCANNING ${lines.length}…`;

      try {
        let results = [];
        if (isBackendConnected) {
          const res = await fetch('/api/batch', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ urls: lines })
          });
          if (res.ok) results = (await res.json()).results || [];
        }
        if (!results.length && window.LinkGuardEngine) {
          results = lines.map(u => window.LinkGuardEngine.analyze(u));
        }
        renderBatchTable(results);
      } catch (err) {
        alert('Batch error: ' + err.message);
      } finally {
        runBatchBtn.disabled = false;
        runBatchBtn.textContent = 'SCAN BATCH';
      }
    });
  }

  function renderBatchTable(results) {
    batchResults.style.display = 'block';
    batchTbody.innerHTML = '';

    const counts = { low: 0, medium: 0, high: 0 };
    results.forEach(r => { counts[r.riskKey || 'low']++; });

    batchSummary.innerHTML =
      `${results.length} URLS PROCESSED &nbsp;·&nbsp; ` +
      `<span style="color:var(--primary)">${counts.low} CLEAN</span> &nbsp;·&nbsp; ` +
      `<span style="color:var(--secondary)">${counts.medium} WARN</span> &nbsp;·&nbsp; ` +
      `<span style="color:var(--hazard)">${counts.high} CRITICAL</span>`;

    results.sort((a, b) => b.score - a.score).forEach((r, i) => {
      const key = riskKey(r.score);
      const col = COLOR[key];
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td style="color:var(--text-muted);font-size:9px;">${i + 1}</td>
        <td style="font-family:var(--font-mono);font-size:10px;word-break:break-all;max-width:360px;">${esc(r.raw)}</td>
        <td><strong style="color:${col.text}">${r.score}</strong></td>
        <td><span class="impact-tag ${key}" style="font-size:9px;">${esc(r.verdict)}</span></td>
        <td style="font-size:10px;color:var(--text-muted);">${r.passedCount || 0}/${(r.passedCount||0)+(r.failedCount||0)}</td>
        <td><button class="analyze-btn" style="height:22px;font-size:9px;padding:0 8px;" data-inspect="${esc(r.raw)}">INSPECT</button></td>
      `;
      tr.querySelector('[data-inspect]').addEventListener('click', () => {
        urlInput.value = r.raw;
        clearBtn.style.display = 'flex';
        document.querySelector('[data-target="viewInspector"]').click();
        runAnalysis();
      });
      batchTbody.appendChild(tr);
    });
  }

});
