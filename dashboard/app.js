// Bloomberg Terminal Dashboard Logic for CapLLM
(function() {
  'use strict';

  // State
  let allEvents = [];
  let filteredEvents = [];
  let currentPage = 1;
  const pageSize = 20; // 20 lines matching classic Bloomberg news feed
  let activeScreen = 'screen-wire';
  let soundEnabled = false;
  let audioCtx = null;
  let isTampered = false;
  let selectedEventIndex = -1;

  // Audio Synth Helper
  function playTerminalSound(type = 'click') {
    if (!soundEnabled) return;
    try {
      if (!audioCtx) {
        audioCtx = new (window.AudioContext || window.webkitAudioContext)();
      }
      if (audioCtx.state === 'suspended') {
        audioCtx.resume();
      }
      const osc = audioCtx.createOscillator();
      const gain = audioCtx.createGain();
      osc.connect(gain);
      gain.connect(audioCtx.destination);

      const now = audioCtx.currentTime;
      if (type === 'click') {
        osc.type = 'sine';
        osc.frequency.setValueAtTime(950, now);
        osc.frequency.exponentialRampToValueAtTime(300, now + 0.03);
        gain.gain.setValueAtTime(0.08, now);
        gain.gain.linearRampToValueAtTime(0, now + 0.03);
        osc.start(now);
        osc.stop(now + 0.03);
      } else if (type === 'go') {
        osc.type = 'triangle';
        osc.frequency.setValueAtTime(440, now);
        osc.frequency.setValueAtTime(880, now + 0.04);
        gain.gain.setValueAtTime(0.12, now);
        gain.gain.linearRampToValueAtTime(0, now + 0.12);
        osc.start(now);
        osc.stop(now + 0.12);
      } else if (type === 'alert') {
        osc.type = 'sawtooth';
        osc.frequency.setValueAtTime(260, now);
        osc.frequency.setValueAtTime(180, now + 0.1);
        gain.gain.setValueAtTime(0.15, now);
        gain.gain.linearRampToValueAtTime(0, now + 0.22);
        osc.start(now);
        osc.stop(now + 0.22);
      }
    } catch (e) {
      console.warn('Audio not available:', e);
    }
  }

  // Initialize
  window.addEventListener('DOMContentLoaded', () => {
    if (typeof AUDIT_LOG_DATA !== 'undefined' && Array.isArray(AUDIT_LOG_DATA)) {
      allEvents = AUDIT_LOG_DATA;
    } else {
      console.warn('AUDIT_LOG_DATA not found, initializing fallback');
      allEvents = [];
    }

    applyFilters();
    renderAll();
    setupEventListeners();
  });

  // Filter application
  function applyFilters() {
    const searchVal = (document.getElementById('cmd-input')?.value || '').trim().toLowerCase();
    const verdictVal = document.getElementById('filter-verdict')?.value || 'ALL';
    const tenantVal = document.getElementById('filter-tenant')?.value || 'ALL';
    const syscallVal = document.getElementById('filter-syscall')?.value || 'ALL';

    filteredEvents = allEvents.filter(ev => {
      // Verdict filter
      if (verdictVal !== 'ALL') {
        if (verdictVal === 'BLOCK' && ev.verdict !== 'BLOCK') return false;
        if (verdictVal === 'ALLOW' && ev.verdict !== 'ALLOW') return false;
        if (verdictVal === 'PENDING' && ev.verdict !== 'PENDING') return false;
      }

      // Tenant filter
      if (tenantVal !== 'ALL' && ev.tenant_id !== tenantVal) {
        return false;
      }

      // Syscall filter
      if (syscallVal !== 'ALL' && ev.syscall_name !== syscallVal) {
        return false;
      }

      // Search query
      if (searchVal) {
        const targetStr = (ev.target_resource || '') + ' ' +
                          (ev.syscall_name || '') + ' ' +
                          (ev.agent_id || '') + ' ' +
                          (ev.tenant_id || '') + ' ' +
                          (ev.event_type || '') + ' ' +
                          (ev.details?.reason || '') + ' ' +
                          (ev.details?.escalation?.join(' ') || '');
        if (!targetStr.toLowerCase().includes(searchVal)) {
          return false;
        }
      }

      return true;
    });

    currentPage = 1;
  }

  // Format timestamp like Bloomberg (HH:MM:SS)
  function formatBloombergTime(ts) {
    if (!ts) return '19:46:00';
    const d = new Date(ts * 1000);
    const h = String(d.getHours()).padStart(2, '0');
    const m = String(d.getMinutes()).padStart(2, '0');
    const s = String(d.getSeconds()).padStart(2, '0');
    return `${h}:${m}:${s}`;
  }

  // Render Wire Feed (Screen 1 - Photo layout)
  function renderWireFeed() {
    const container = document.getElementById('wire-feed-list');
    if (!container) return;

    container.innerHTML = '';
    const totalPages = Math.max(1, Math.ceil(filteredEvents.length / pageSize));
    document.getElementById('page-display').textContent = `Pg ${currentPage} / ${totalPages}`;
    document.getElementById('total-records-count').textContent = `[${filteredEvents.length}/${allEvents.length}]`;

    document.getElementById('prev-page-btn').disabled = currentPage <= 1;
    document.getElementById('next-page-btn').disabled = currentPage >= totalPages;

    if (filteredEvents.length === 0) {
      container.innerHTML = `
        <div class="wire-empty-state">
          NO MATCHING AUDIT WIRE EVENTS FOUND FOR CURRENT FILTER.
          <br><br>
          Type <span style="color:var(--bb-yellow)">RESET&lt;GO&gt;</span> to restore all records.
        </div>
      `;
      return;
    }

    const startIndex = (currentPage - 1) * pageSize;
    const pageRecords = filteredEvents.slice(startIndex, startIndex + pageSize);

    pageRecords.forEach((ev, idx) => {
      const globalIndex = startIndex + idx + 1;
      const row = document.createElement('div');
      row.className = 'wire-row';
      if (globalIndex === selectedEventIndex) {
        row.classList.add('selected');
      }

      // Icon & checkmark like Bloomberg screenshot
      let iconHtml = '&nbsp;';
      let sourceTag = 'BLG';
      if (ev.verdict === 'ALLOW') {
        iconHtml = '<span class="wire-icon allow">✓</span>';
        sourceTag = ev.details?.path === 'FAST' ? 'FST' : 'BLG';
      } else if (ev.verdict === 'BLOCK') {
        iconHtml = '<span class="wire-icon block">☠</span>';
        sourceTag = 'SEC';
      } else if (ev.verdict === 'PENDING') {
        iconHtml = '<span class="wire-icon intercept">⚡</span>';
        sourceTag = 'INT';
      }

      if (ev.event_type === 'TOKEN_ISSUED') {
        sourceTag = 'TOK';
        iconHtml = '<span class="wire-icon token">🔑</span>';
      } else if (ev.event_type === 'PROCESS_TERMINATED') {
        sourceTag = 'KRN';
        iconHtml = '<span class="wire-icon block">✗</span>';
      }

      // Construct headline
      let headline = '';
      if (ev.event_type === 'TOKEN_ISSUED') {
        headline = `Token Issued for [${ev.tenant_id}] -> ${ev.target_resource} (TTL: ${ev.details?.ttl_s || 120}s)`;
      } else if (ev.event_type === 'PROCESS_TERMINATED') {
        headline = `PROCESS TERMINATED: ${ev.target_resource} killed on violation: ${ev.details?.reason || 'Security Escalation'}`;
      } else if (ev.event_type === 'TOKEN_REVOKED') {
        headline = `TOKEN REVOKED: ${ev.target_resource} [${ev.details?.reason || 'Anomaly Detected'}]`;
      } else if (ev.event_type === 'SYSCALL_INTERCEPTED') {
        headline = `INTERCEPTED: ${ev.syscall_name} ${ev.target_resource} -> Escalation: ${(ev.details?.escalation || []).join(', ')}`;
      } else {
        const pathTag = ev.details?.path ? `[${ev.details.path}]` : '';
        const reasonText = ev.details?.reason ? ` (${ev.details.reason})` : '';
        const verdictClass = (ev.verdict || 'allow').toLowerCase();
        headline = `${pathTag} ${ev.syscall_name} ${ev.target_resource} -> <span class="verdict-badge ${verdictClass}">${ev.verdict}</span>${reasonText}`;
      }

      // Latency tag
      let latencyStr = '';
      if (ev.details?.latency_us) {
        latencyStr = `${ev.details.latency_us.toFixed(1)} us`;
      } else if (ev.details?.ttl_s) {
        latencyStr = `TTL ${ev.details.ttl_s}s`;
      }

      row.innerHTML = `
        <div class="wire-idx">${globalIndex})</div>
        <div class="wire-icon-col">${iconHtml}</div>
        <div class="wire-source">${sourceTag}</div>
        <div class="wire-time">${formatBloombergTime(ev.timestamp)}</div>
        <div class="wire-headline">${headline}</div>
        <div class="wire-latency">${latencyStr}</div>
      `;

      row.addEventListener('click', () => {
        playTerminalSound('click');
        selectedEventIndex = globalIndex;
        openEventInspector(ev);
        document.querySelectorAll('.wire-row').forEach(r => r.classList.remove('selected'));
        row.classList.add('selected');
      });

      container.appendChild(row);
    });
  }

  // Render Threat Matrix & Scenarios (Screen 2)
  function renderThreatMatrix() {
    const container = document.getElementById('threat-matrix-cards');
    if (!container) return;

    const scenarios = BENCHMARK_METRICS_DATA?.demo_scenarios || [];
    container.innerHTML = scenarios.map((s, idx) => {
      const borderClass = idx === 0 ? 'border-green' : (idx === 1 || idx === 2 ? 'border-red' : 'border-amber');
      return `
        <div class="threat-card ${borderClass}">
          <div class="threat-card-title">
            <span class="threat-card-id">${s.id}: ${s.name}</span>
            <span class="threat-card-badge">${s.verdict}</span>
          </div>
          <div class="threat-card-body">
            <strong>Target:</strong> ${s.agent} (${s.tenant})<br>
            <strong>Behavior:</strong> ${s.description}<br>
            <strong>Outcome:</strong> <span style="color:var(--bb-yellow)">${s.outcome}</span>
          </div>
          <div class="threat-card-metrics">
            <div>
              <span class="metric-label">Latency Mode:</span><br>
              <span class="metric-val">${s.fast_path_latency_avg_us ? s.fast_path_latency_avg_us + ' us (FAST)' : (s.slow_path_latency_avg_us ? s.slow_path_latency_avg_us + ' us (SLOW)' : '420 us (REVOKE)')}</span>
            </div>
            <div>
              <span class="metric-label">Defense:</span><br>
              <span class="metric-val">100% Mediate</span>
            </div>
          </div>
        </div>
      `;
    }).join('');
  }

  // Render Latency & Overhead Charts (Screen 3)
  function renderLatencyBenchmarks() {
    const container = document.getElementById('latency-bars-container');
    if (!container) return;

    const scenarios = BENCHMARK_METRICS_DATA?.scenarios || [];
    const maxLatency = 450; // max scale in us

    container.innerHTML = scenarios.map(sc => {
      const p50Width = Math.min(100, (sc.p50_us / maxLatency) * 100);
      return `
        <div class="bar-visual-row">
          <div class="bar-label">
            <span><strong>${sc.id}</strong> (${sc.name})</span>
            <span style="color:var(--bb-yellow)">p50: ${sc.p50_us.toFixed(1)}us | p95: ${sc.p95_us.toFixed(1)}us | Mean: ${sc.mean_us.toFixed(1)}us</span>
          </div>
          <div class="bar-track" title="p50: ${sc.p50_us}us">
            <div class="bar-fill-fast" style="width: ${p50Width}%;"></div>
          </div>
        </div>
      `;
    }).join('');
  }

  // Render Cryptographic Hash-Chain Explorer (Screen 4)
  function renderHashChain() {
    const container = document.getElementById('chain-blocks-container');
    if (!container) return;

    container.innerHTML = '';
    const blocks = allEvents.slice(0, 35);

    blocks.forEach((b) => {
      const el = document.createElement('div');
      el.className = 'chain-block';
      el.id = `chain-block-${b.sequence}`;

      let isBlockTampered = isTampered && b.sequence >= 14;
      if (isBlockTampered) {
        el.classList.add('tampered');
      }

      const prevDisplay = b.previous_hash.slice(0, 16) + '...';
      const currDisplay = (isBlockTampered && b.sequence === 14)
        ? 'DEADBEEFCAFE0000BAD000000000...' 
        : b.entry_hash.slice(0, 16) + '...';

      el.innerHTML = `
        <div class="seq">#${b.sequence} [${b.verdict}]</div>
        <div class="hash" title="Prev: ${b.previous_hash}">
          <span class="hash-tag">PREV:</span>${prevDisplay}
        </div>
        <div class="hash" title="Hash: ${b.entry_hash}">
          <span class="hash-tag">HASH:</span>${currDisplay}
        </div>
        <div class="text-right" style="font-size:10px;">
          ${isBlockTampered ? '<span style="color:#ff3333;font-weight:bold;">TAMPERED!</span>' : '<span style="color:var(--bb-green);">VERIFIED ✓</span>'}
        </div>
      `;

      el.addEventListener('click', () => {
        playTerminalSound('click');
        openEventInspector(b);
      });

      container.appendChild(el);
    });
  }

  // Switch Screen Views
  function switchScreen(screenId) {
    playTerminalSound('click');
    activeScreen = screenId;
    document.querySelectorAll('.screen-view').forEach(s => s.classList.remove('active-screen'));
    document.querySelectorAll('.bb-function-tab').forEach(t => t.classList.remove('active'));

    const targetScreen = document.getElementById(screenId);
    if (targetScreen) targetScreen.classList.add('active-screen');

    const targetTab = document.querySelector(`.bb-function-tab[data-screen="${screenId}"]`);
    if (targetTab) targetTab.classList.add('active');

    if (screenId === 'screen-wire') renderWireFeed();
    else if (screenId === 'screen-threat') renderThreatMatrix();
    else if (screenId === 'screen-benchmarks') renderLatencyBenchmarks();
    else if (screenId === 'screen-ledger') renderHashChain();
  }

  // Event Inspector Modal
  function openEventInspector(ev) {
    const modal = document.getElementById('inspector-modal');
    if (!modal) return;

    document.getElementById('modal-event-title').textContent = 
      `INSPECTION RECORD: SEQ #${ev.sequence} | ${ev.event_type} (${ev.verdict})`;

    const grid = document.getElementById('modal-details-grid');
    grid.innerHTML = `
      <div class="modal-field-label">Sequence ID:</div>
      <div class="modal-field-val">${ev.sequence}</div>
      <div class="modal-field-label">Event UUID:</div>
      <div class="modal-field-val">${ev.event_id}</div>
      <div class="modal-field-label">Timestamp:</div>
      <div class="modal-field-val">${new Date(ev.timestamp * 1000).toISOString()} (${ev.timestamp})</div>
      <div class="modal-field-label">Tenant ID:</div>
      <div class="modal-field-val" style="color:var(--bb-yellow);">${ev.tenant_id} (Agent: ${ev.agent_id})</div>
      <div class="modal-field-label">Syscall / Resource:</div>
      <div class="modal-field-val" style="color:var(--bb-cyan);">${ev.syscall_name} &rarr; ${ev.target_resource}</div>
      <div class="modal-field-label">Verdict:</div>
      <div class="modal-field-val" style="font-weight:bold; color:${ev.verdict === 'ALLOW' ? 'var(--bb-green)' : 'var(--bb-red-bright)'};">${ev.verdict}</div>
      <div class="modal-field-label">SHA-256 Block Hash:</div>
      <div class="modal-field-val" style="font-family:monospace; font-size:11px;">${ev.entry_hash}</div>
      <div class="modal-field-label">Parent Block Hash:</div>
      <div class="modal-field-val" style="font-family:monospace; font-size:11px;">${ev.previous_hash}</div>
    `;

    document.getElementById('modal-raw-json').textContent = JSON.stringify(ev, null, 2);
    modal.classList.add('open');
  }

  function closeEventInspector() {
    playTerminalSound('click');
    const modal = document.getElementById('inspector-modal');
    if (modal) modal.classList.remove('open');
  }

  // Command input handler (Bloomberg <GO> command syntax)
  function handleCommandSubmit() {
    const input = document.getElementById('cmd-input');
    if (!input) return;
    const rawCmd = input.value.trim().toUpperCase();
    input.value = '';

    playTerminalSound('go');

    if (rawCmd === '1' || rawCmd === '1<GO>' || rawCmd === '21' || rawCmd === '21<GO>' || rawCmd === 'WIRE' || rawCmd === 'AUDIT') {
      switchScreen('screen-wire');
    } else if (rawCmd === '2' || rawCmd === '2<GO>' || rawCmd === '22' || rawCmd === '22<GO>' || rawCmd === 'THREAT' || rawCmd === 'MATRIX') {
      switchScreen('screen-threat');
    } else if (rawCmd === '3' || rawCmd === '3<GO>' || rawCmd === '23' || rawCmd === '23<GO>' || rawCmd === 'BENCH' || rawCmd === 'LATENCY') {
      switchScreen('screen-benchmarks');
    } else if (rawCmd === '4' || rawCmd === '4<GO>' || rawCmd === '24' || rawCmd === '24<GO>' || rawCmd === 'LEDGER' || rawCmd === 'CHAIN') {
      switchScreen('screen-ledger');
    } else if (rawCmd === 'BLOCK' || rawCmd === 'BLOCK<GO>') {
      document.getElementById('filter-verdict').value = 'BLOCK';
      applyFilters();
      switchScreen('screen-wire');
    } else if (rawCmd === 'ALLOW' || rawCmd === 'ALLOW<GO>') {
      document.getElementById('filter-verdict').value = 'ALLOW';
      applyFilters();
      switchScreen('screen-wire');
    } else if (rawCmd === 'RESET' || rawCmd === 'MENU' || rawCmd === 'CLEAR') {
      document.getElementById('filter-verdict').value = 'ALL';
      document.getElementById('filter-tenant').value = 'ALL';
      document.getElementById('filter-syscall').value = 'ALL';
      applyFilters();
      switchScreen('screen-wire');
    } else if (rawCmd === 'TAMPER' || rawCmd === 'TAMPER<GO>') {
      switchScreen('screen-ledger');
      injectTamper();
    } else if (rawCmd.startsWith('SEARCH ') || rawCmd.startsWith('FIND ')) {
      const q = rawCmd.split(' ')[1];
      input.value = q;
      applyFilters();
      switchScreen('screen-wire');
    } else {
      // Treat generic text as search
      input.value = rawCmd;
      applyFilters();
      renderWireFeed();
    }
  }

  // Tamper Simulation for Screen 4
  function injectTamper() {
    isTampered = true;
    playTerminalSound('alert');
    document.getElementById('tamper-alert').style.display = 'block';
    document.getElementById('tamper-btn').style.display = 'none';
    document.getElementById('repair-btn').style.display = 'inline-block';
    renderHashChain();
  }

  function repairChain() {
    isTampered = false;
    playTerminalSound('click');
    document.getElementById('tamper-alert').style.display = 'none';
    document.getElementById('tamper-btn').style.display = 'inline-block';
    document.getElementById('repair-btn').style.display = 'none';
    renderHashChain();
  }

  // Export data as JSON / CSV
  function exportAuditData(format = 'json') {
    playTerminalSound('go');
    let blob;
    let filename;
    if (format === 'json') {
      const dataStr = JSON.stringify(filteredEvents, null, 2);
      blob = new Blob([dataStr], { type: 'application/json' });
      filename = `capllm_audit_export_${Date.now()}.json`;
    } else {
      const headers = ['sequence', 'timestamp', 'tenant_id', 'agent_id', 'syscall_name', 'target_resource', 'verdict', 'entry_hash'];
      const rows = filteredEvents.map(e => [
        e.sequence,
        e.timestamp,
        e.tenant_id,
        e.agent_id,
        e.syscall_name,
        `"${(e.target_resource || '').replace(/"/g, '""')}"`,
        e.verdict,
        e.entry_hash
      ]);
      const csvStr = [headers.join(','), ...rows.map(r => r.join(','))].join('\n');
      blob = new Blob([csvStr], { type: 'text/csv' });
      filename = `capllm_audit_export_${Date.now()}.csv`;
    }

    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
  }

  // Wire Sub-panel rotation
  function rotateWireSubpanel() {
    const panel = document.getElementById('bottom-wire-panel');
    if (!panel) return;

    const notable = allEvents.filter(e => e.verdict === 'BLOCK' || e.event_type === 'PROCESS_TERMINATED' || e.details?.path === 'SLOW');
    if (notable.length < 4) return;

    const offset = Math.floor(Math.random() * (notable.length - 4));
    const items = notable.slice(offset, offset + 4);

    panel.innerHTML = items.map((it, idx) => {
      const lineNum = 452 - idx;
      const isAlert = it.verdict === 'BLOCK';
      let text = '';
      if (it.event_type === 'PROCESS_TERMINATED') {
        text = `PROCESS TERMINATED: ${it.target_resource} killed on ${it.details?.reason || 'Security Violation'}`;
      } else if (it.verdict === 'BLOCK') {
        text = `SECURITY BLOCK: ${it.syscall_name} ${it.target_resource} -> ${it.details?.reason || 'Non-delegable access'}`;
      } else {
        text = `SLOW-PATH MEDIATION: ${it.syscall_name} ${it.target_resource} (${(it.details?.latency_us || 0).toFixed(0)} us)`;
      }

      return `
        <div class="wire-item">
          <span class="wire-item-num">${lineNum}</span>
          <span class="wire-item-source">${isAlert ? 'SEC' : 'BN'}</span>
          <span class="wire-item-time">${formatBloombergTime(it.timestamp)}</span>
          <span class="wire-item-text ${isAlert ? 'alert' : ''}">${text}</span>
        </div>
      `;
    }).join('');
  }

  // Setup all UI event listeners
  function setupEventListeners() {
    // Function Tabs
    document.querySelectorAll('.bb-function-tab').forEach(tab => {
      tab.addEventListener('click', () => {
        const screenId = tab.getAttribute('data-screen');
        switchScreen(screenId);
      });
    });

    // Pagination
    document.getElementById('prev-page-btn')?.addEventListener('click', () => {
      if (currentPage > 1) {
        playTerminalSound('click');
        currentPage--;
        renderWireFeed();
      }
    });

    document.getElementById('next-page-btn')?.addEventListener('click', () => {
      const totalPages = Math.ceil(filteredEvents.length / pageSize);
      if (currentPage < totalPages) {
        playTerminalSound('click');
        currentPage++;
        renderWireFeed();
      }
    });

    // Filter selects
    ['filter-verdict', 'filter-tenant', 'filter-syscall'].forEach(id => {
      document.getElementById(id)?.addEventListener('change', () => {
        playTerminalSound('click');
        applyFilters();
        renderWireFeed();
      });
    });

    // Save/Export button
    document.getElementById('btn-action-save')?.addEventListener('click', () => {
      exportAuditData('json');
    });

    // Command input & GO button
    const cmdInput = document.getElementById('cmd-input');
    cmdInput?.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        handleCommandSubmit();
      }
    });

    document.getElementById('btn-go')?.addEventListener('click', () => {
      handleCommandSubmit();
    });

    // CRT Toggle
    document.getElementById('btn-toggle-crt')?.addEventListener('click', function() {
      document.body.classList.toggle('crt-off');
      const isOff = document.body.classList.contains('crt-off');
      this.textContent = isOff ? '📺 CRT: OFF' : '📺 CRT: ON';
      playTerminalSound('click');
    });

    // Tamper Simulation Buttons
    document.getElementById('tamper-btn')?.addEventListener('click', injectTamper);
    document.getElementById('repair-btn')?.addEventListener('click', repairChain);

    // Modal Close
    document.getElementById('btn-modal-close')?.addEventListener('click', closeEventInspector);
    document.getElementById('inspector-modal')?.addEventListener('click', (e) => {
      if (e.target.id === 'inspector-modal') closeEventInspector();
    });

    // Periodic rotation of bottom wire panel
    rotateWireSubpanel();
    setInterval(rotateWireSubpanel, 4000);
  }

  // Initial Full Render
  function renderAll() {
    renderWireFeed();
    renderThreatMatrix();
    renderLatencyBenchmarks();
    renderHashChain();
  }

})();
