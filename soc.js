/* ═══════════════════════════════════════════════════════════════
   soc.js — Enterprise SOC Console  |  Frontend Logic
   ═══════════════════════════════════════════════════════════════ */

'use strict';

let attackChart   = null;
let riskChart     = null;
let timerInterval = null;
let timerSeconds  = 60;
const TIMEOUT_MS  = 60000;

/* ───────────────────────────────────────────
   CLOCK
─────────────────────────────────────────── */
function tickClock() {
  const now = new Date();
  const ist = new Date(now.getTime() + 5.5 * 3600000);
  const hh  = String(ist.getUTCHours()).padStart(2,'0');
  const mm  = String(ist.getUTCMinutes()).padStart(2,'0');
  const ss  = String(ist.getUTCSeconds()).padStart(2,'0');
  document.getElementById('socClock').textContent = `${hh}:${mm}:${ss}`;
}
tickClock();
setInterval(tickClock, 1000);

/* ───────────────────────────────────────────
   TIMER
─────────────────────────────────────────── */
function startTimer() {
  timerSeconds = 60;
  const wrap  = document.getElementById('timerWrap');
  const fill  = document.getElementById('timerFill');
  const count = document.getElementById('timerCountdown');
  wrap.classList.add('active');
  fill.style.width  = '100%';
  fill.className    = 'timer-fill';
  count.textContent = '01:00';
  clearInterval(timerInterval);
  timerInterval = setInterval(() => {
    timerSeconds--;
    const pct = (timerSeconds / 60) * 100;
    fill.style.width  = pct + '%';
    const m = String(Math.floor(timerSeconds / 60)).padStart(2,'0');
    const s = String(timerSeconds % 60).padStart(2,'0');
    count.textContent = `${m}:${s}`;
    if (timerSeconds <= 20) fill.className = 'timer-fill warning';
    if (timerSeconds <= 10) fill.className = 'timer-fill danger';
    if (timerSeconds <= 0)  stopTimer(true);
  }, 1000);
}

function stopTimer(timedOut = false) {
  clearInterval(timerInterval);
  const wrap  = document.getElementById('timerWrap');
  const fill  = document.getElementById('timerFill');
  const count = document.getElementById('timerCountdown');
  if (timedOut) {
    fill.style.width  = '0%';
    count.textContent = '00:00';
  } else {
    wrap.classList.remove('active');
  }
}

function resetUI() {
  const btn = document.getElementById('analyzeBtn');
  btn.disabled    = false;
  btn.textContent = '▶   Analyze Logs';
  stopTimer(false);
}

/* ───────────────────────────────────────────
   MAIN — ANALYZE
─────────────────────────────────────────── */
async function analyze() {
  let logs = '';
  const file = document.getElementById('file').files[0];
  const text = document.getElementById('logText').value.trim();

  if (text)      logs = text;
  else if (file) logs = await file.text();
  else { alert('Please provide log data.'); return; }

  const btn    = document.getElementById('analyzeBtn');
  const result = document.getElementById('result');
  btn.disabled    = true;
  btn.textContent = '⏳  Analyzing…';
  result.className   = 'raw-out';
  result.textContent = 'Analyzing logs — please wait…';
  startTimer();

  const controller  = new AbortController();
  const hardTimeout = setTimeout(() => controller.abort(), TIMEOUT_MS);

  try {
    const res = await fetch('analyze.php', {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ logs }),
      signal:  controller.signal
    });

    clearTimeout(hardTimeout);
    stopTimer(false);

    const data = await res.json();
    result.className   = 'raw-out';
    result.textContent = data.result || '(no output)';

    /* ── PRIMARY: use PHP's already-parsed structured array ── */
    let incidents = [];

    if (Array.isArray(data.incidents) && data.incidents.length > 0) {
      incidents = data.incidents.map(inc => ({
        type:     cleanStr(inc['Attack Type']),
        severity: cleanStr(inc['Severity']),
        source:   cleanStr(inc['Source'])
      }));
    }

    /* ── FALLBACK: parse the raw AI text ourselves ──
       Triggered when PHP returned 0 incidents (e.g. all below
       confidence threshold) but the raw text has incident blocks. */
    if (incidents.length === 0 && data.result) {
      incidents = parseRawAI(data.result);
    }

    if (incidents.length === 0) {
      renderTable([]);
      renderCharts([]);
      updateKPIs([]);
      return;
    }

    renderTable(incidents);
    renderCharts(incidents);
    updateKPIs(incidents);

  } catch (err) {
    clearTimeout(hardTimeout);
    stopTimer(true);
    if (err.name === 'AbortError') {
      result.className   = 'raw-out timeout';
      result.textContent = '⚠ TIMEOUT: Analysis exceeded 60 seconds.\nPlease try again with fewer logs.';
    } else {
      result.className   = 'raw-out error';
      result.textContent = '⚠ ERROR: ' + err.message;
    }
  } finally {
    resetUI();
  }
}

/* ───────────────────────────────────────────
   PARSE RAW AI TEXT  (fallback)
   ─────────────────────────────────────────
   THE FIX:
   The AI wraps every field label AND value in **bold**, e.g.:
     **Attack Type:** SQL Injection
     **Severity:** High
   Simple split('Incident:') + /Attack Type:\s*(.*)/i failed
   because ** before the label breaks the match.

   Solution: strip ALL markdown first, THEN regex on clean text.
─────────────────────────────────────────── */
function parseRawAI(rawText) {
  /* 1. Strip markdown */
  let t = rawText
    .replace(/\*{1,3}/g,  '')          // *** ** *
    .replace(/_{1,2}/g,   '')          // __ _
    .replace(/`([^`]*)`/g, '$1')       // `code`
    .replace(/^#+\s*/gm,  '');         // ## headings

  /* 2. Split on "Incident" boundary — tolerates numbering & spacing */
  const blocks = t.split(/^\s*(?:[-\d.]+\s*)?Incident\s*\d*\s*:/mi);

  const incidents = [];

  blocks.forEach(block => {
    block = block.trim();
    if (!block) return;

    const extract = (re, fallback) => {
      const m = block.match(re);
      if (!m) return fallback;
      return m[1].replace(/[*_`]/g, '').trim() || fallback;
    };

    const type     = extract(/Attack\s*Type\s*:\s*(.+)/i,  '');
    const severity = extract(/Severity\s*:\s*(.+)/i,        'Low');
    const source   = extract(/Source\s*:\s*(.+)/i,          'N/A');

    /* Only push if we found at least an attack type */
    if (type) {
      incidents.push({
        type:     normalizeSeverityWord(type),      // keep as-is for type
        severity: normalizeSeverity(severity),
        source
      });
    }
  });

  return incidents;

  /* local helpers */
  function normalizeSeverity(s) {
    const m = s.match(/\b(low|medium|high|critical)\b/i);
    if (!m) return 'Medium';
    return m[1].charAt(0).toUpperCase() + m[1].slice(1).toLowerCase();
  }
  function normalizeSeverityWord(s) { return s; } // passthrough for type
}

/* ───────────────────────────────────────────
   KPI CARDS
─────────────────────────────────────────── */
function updateKPIs(data) {
  let critical = 0, high = 0;
  data.forEach(i => {
    const s = i.severity.toLowerCase();
    if      (s.includes('critical')) critical++;
    else if (s.includes('high'))     high++;
  });
  const score = Math.min(100, Math.round((critical * 4 + high * 2 + (data.length - critical - high)) * 3));
  document.getElementById('kpiTotal').textContent    = data.length;
  document.getElementById('kpiCritical').textContent = critical;
  document.getElementById('kpiHigh').textContent     = high;
  document.getElementById('kpiRisk').textContent     = score;
  document.getElementById('incidentCount').textContent =
    data.length + ' event' + (data.length !== 1 ? 's' : '');
}

/* ───────────────────────────────────────────
   INCIDENT TABLE
─────────────────────────────────────────── */
function renderTable(data) {
  const tbody = document.getElementById('incidentTable');
  if (!data.length) {
    tbody.innerHTML = '<tr><td colspan="3" class="empty-state">No incidents detected</td></tr>';
    return;
  }
  tbody.innerHTML = data.map(i => {
    const s   = i.severity.toLowerCase();
    const cls = s.includes('critical') ? 'critical' :
                s.includes('high')     ? 'high'     :
                s.includes('medium')   ? 'medium'   : 'low';
    return `<tr>
      <td>${esc(i.type)}</td>
      <td><span class="badge ${cls}">${esc(i.severity)}</span></td>
      <td>${esc(i.source)}</td>
    </tr>`;
  }).join('');
}

/* ───────────────────────────────────────────
   CHARTS
─────────────────────────────────────────── */
function renderCharts(data) {
  const attacks = {};
  const risk    = { low:0, medium:0, high:0, critical:0 };

  data.forEach(i => {
    const t = i.type || 'Unknown';
    attacks[t] = (attacks[t] || 0) + 1;
    const s = i.severity.toLowerCase();
    if      (s.includes('critical')) risk.critical++;
    else if (s.includes('high'))     risk.high++;
    else if (s.includes('medium'))   risk.medium++;
    else                             risk.low++;
  });

  drawAttackChart(attacks);
  drawRiskChart(risk);
}

function drawAttackChart(data) {
  if (attackChart) attackChart.destroy();
  attackChart = new Chart(document.getElementById('attackChart'), {
    type: 'doughnut',
    data: {
      labels: Object.keys(data),
      datasets: [{
        data: Object.values(data),
        backgroundColor: ['#ff2244cc','#ff7a00cc','#ffe600cc','#0cf4e8cc','#4da6ffcc','#aa44ffcc','#00cc6ecc','#ff44aacc'],
        borderColor:  '#0b1530',
        borderWidth:  3,
        hoverOffset:  8
      }]
    },
    options: {
      maintainAspectRatio: false,
      cutout: '55%',
      layout: { padding: 10 },
      plugins: {
        legend: {
          position: 'right',
          labels: {
            color: '#6a8aaa',
            font: { size: 10, family: 'Share Tech Mono' },
            padding: 10, boxWidth: 10, boxHeight: 10,
            usePointStyle: true, pointStyleWidth: 10
          }
        }
      }
    }
  });
}

function drawRiskChart(data) {
  if (riskChart) riskChart.destroy();
  riskChart = new Chart(document.getElementById('riskChart'), {
    type: 'bar',
    data: {
      labels: ['Low','Med','High','Crit'],
      datasets: [{
        data: [data.low, data.medium, data.high, data.critical],
        backgroundColor: ['#00cc6e30','#d4bc0030','#ff7a0030','#ff224430'],
        borderColor:     ['#00cc6e',  '#d4bc00',  '#ff7a00',  '#ff2244'],
        borderWidth: 1.5,
        borderRadius: 4
      }]
    },
    options: {
      maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: {
        x: { ticks:{ color:'#3a5070', font:{ size:9, family:'Share Tech Mono' } }, grid:{ color:'#0cf4e810' } },
        y: { ticks:{ color:'#3a5070', font:{ size:9, family:'Share Tech Mono' } }, grid:{ color:'#0cf4e810' }, beginAtZero: true }
      }
    }
  });
}

/* ───────────────────────────────────────────
   UTILITIES
─────────────────────────────────────────── */
function cleanStr(val) {
  if (!val || val === 'N/A') return val || 'N/A';
  return String(val).replace(/\*{1,3}/g,'').replace(/_{1,2}/g,'').replace(/`/g,'').trim();
}

function esc(str) {
  return String(str||'')
    .replace(/&/g,'&amp;').replace(/</g,'&lt;')
    .replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}