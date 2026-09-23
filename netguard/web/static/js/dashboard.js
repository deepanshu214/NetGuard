/**
 * NetGuard Dashboard Client Script
 */

let socket = null;
let bandwidthChart = null;
let protocolChart = null;

let allAlerts = [];
let activeFilter = "ALL";

let packetBuffer = [];
let packetCounter = 0;
let isStreamPaused = false;
let packetProtoFilter = "ALL";

document.addEventListener("DOMContentLoaded", () => {
    initCharts();
    initSocketIO();
    fetchInitialData();
    refreshConnections();
    setInterval(updateUptime, 1000);
    setInterval(updateUTCClock, 1000);
    setInterval(refreshConnections, 3000);
    updateUTCClock();
});

// =============================================================================
// 1. Tab Switching
// =============================================================================
function switchTab(tabName, btnEl) {
    document.querySelectorAll('.nav-item').forEach(b => b.classList.remove('active'));
    if (btnEl) btnEl.classList.add('active');

    document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
    const pane = document.getElementById(`tab-${tabName}`);
    if (pane) pane.classList.add('active');

    document.getElementById('sidebar').classList.remove('open');

    if (tabName === 'config') {
        loadCurrentConfig();
        loadEmailSettings();
    } else if (tabName === 'connections') {
        refreshConnections();
    } else if (tabName === 'threatmap') {
        setTimeout(() => {
            initThreatMap();
            if (threatMap) threatMap.invalidateSize();
            refreshThreatMap();
        }, 100);
    } else if (tabName === 'blacklist') {
        loadBlacklist();
    }
}

function toggleSidebar() {
    document.getElementById('sidebar').classList.toggle('open');
}

// =============================================================================
// 2. Chart.js Setup
// =============================================================================
function initCharts() {
    Chart.defaults.color = '#6b7280';
    Chart.defaults.borderColor = '#1b1f27';
    Chart.defaults.font.family = "'Geist', sans-serif";

    const bwCtx = document.getElementById('bandwidthChart').getContext('2d');
    bandwidthChart = new Chart(bwCtx, {
        type: 'line',
        data: {
            labels: [],
            datasets: [
                {
                    label: 'Throughput (KB/s)',
                    data: [],
                    borderColor: '#3b82f6',
                    backgroundColor: 'rgba(59, 130, 246, 0.06)',
                    fill: true,
                    tension: 0.3,
                    borderWidth: 1.5,
                    yAxisID: 'y',
                    pointRadius: 0
                },
                {
                    label: 'Packet Rate (pps)',
                    data: [],
                    borderColor: '#6366f1',
                    backgroundColor: 'transparent',
                    fill: false,
                    tension: 0.3,
                    borderWidth: 1,
                    yAxisID: 'y1',
                    pointRadius: 0,
                    borderDash: [4, 2]
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            animation: false,
            scales: {
                x: { grid: { color: 'rgba(33,38,49,0.6)' }, ticks: { maxTicksLimit: 8, font: { size: 10, family: "'JetBrains Mono', monospace" } } },
                y: { type: 'linear', position: 'left', beginAtZero: true, grid: { color: 'rgba(33,38,49,0.6)' }, ticks: { font: { size: 10, family: "'JetBrains Mono', monospace" } } },
                y1: { type: 'linear', position: 'right', beginAtZero: true, grid: { drawOnChartArea: false }, ticks: { font: { size: 10, family: "'JetBrains Mono', monospace" } } }
            },
            plugins: {
                legend: { labels: { boxWidth: 8, font: { size: 11, weight: '500' }, padding: 12 } }
            }
        }
    });

    const protoCtx = document.getElementById('protocolChart').getContext('2d');
    protocolChart = new Chart(protoCtx, {
        type: 'doughnut',
        data: {
            labels: ['TCP', 'UDP', 'ICMP', 'OTHER'],
            datasets: [{ data: [0,0,0,0], backgroundColor: ['#3b82f6','#6366f1','#f59e0b','#4b5563'], borderColor: '#12151b', borderWidth: 2 }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            cutout: '72%',
            plugins: { legend: { position: 'bottom', labels: { boxWidth: 8, padding: 8, font: { size: 10 } } } }
        }
    });
}

// =============================================================================
// 3. WebSocket
// =============================================================================
function initSocketIO() {
    socket = io();
    const dot = document.getElementById('status-dot');
    const statusText = document.getElementById('connection-status');

    socket.on('connect', () => {
        if (dot) dot.classList.remove('disconnected');
        statusText.textContent = 'Engine Active';
    });
    socket.on('disconnect', () => {
        if (dot) dot.classList.add('disconnected');
        statusText.textContent = 'Disconnected';
    });
    socket.on('metrics', (data) => { handleMetricUpdate(data); });
    socket.on('alert', (alert) => { handleNewAlert(alert); });
    socket.on('packet', (pkt) => { handleNewPacket(pkt); });
}

// =============================================================================
// 4. Telemetry Updates
// =============================================================================
function handleMetricUpdate(m) {
    document.getElementById('kpi-total-packets').textContent = m.total_packets.toLocaleString();

    const ppsEl = document.getElementById('kpi-pps-delta');
    if (ppsEl) ppsEl.textContent = `+${m.pps} pps`;

    const kbPerSec = (m.bps / 1024).toFixed(1);
    document.getElementById('kpi-throughput').innerHTML = `${kbPerSec} <span class="unit">KB/s</span>`;
    document.getElementById('kpi-kbps').textContent = `${m.kbps} Kbps`;

    const dropsEl = document.getElementById('kpi-drops');
    if (dropsEl) dropsEl.textContent = m.drop_count || 0;

    if (m.active_flows_count !== undefined) {
        document.getElementById('kpi-flows').textContent = m.active_flows_count;
    }

    // Ring buffer display
    const ringEl = document.getElementById('ringbuf-display');
    if (ringEl) ringEl.textContent = `${m.total_packets % 1000} / 1000`;

    // Sub-KPI values
    const subPps = document.getElementById('sub-pps');
    if (subPps) subPps.textContent = m.pps || 0;
    const subDrops = document.getElementById('sub-drops');
    if (subDrops) subDrops.textContent = m.drop_count || 0;

    // Header alert badge
    updateHeaderAlertBadge();

    // Bandwidth chart
    const timeLabel = new Date(m.ts * 1000).toLocaleTimeString([], { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });
    const labels = bandwidthChart.data.labels;
    const kbData = bandwidthChart.data.datasets[0].data;
    const ppsData = bandwidthChart.data.datasets[1].data;

    labels.push(timeLabel);
    kbData.push(parseFloat(kbPerSec));
    ppsData.push(m.pps);

    if (labels.length > 60) { labels.shift(); kbData.shift(); ppsData.shift(); }
    bandwidthChart.update('none');

    // Protocol chart
    if (m.protocol_counts) {
        protocolChart.data.datasets[0].data = [
            m.protocol_counts['TCP'] || 0,
            m.protocol_counts['UDP'] || 0,
            m.protocol_counts['ICMP'] || 0,
            m.protocol_counts['OTHER'] || 0
        ];
        protocolChart.update('none');
    }

    // Top hosts (rendered as ranked cards)
    if (m.top_talkers) {
        renderTopHosts(m.top_talkers);
    }
}

function renderTopHosts(talkers) {
    const container = document.getElementById('top-hosts-list');
    const countBadge = document.getElementById('top-hosts-count');
    if (!container) return;

    if (!talkers || talkers.length === 0) {
        container.innerHTML = '<div style="text-align:center;color:var(--text-muted);padding:1.5rem;font-size:12px;">No hosts detected yet.</div>';
        if (countBadge) countBadge.textContent = '0 unique';
        return;
    }

    if (countBadge) countBadge.textContent = `${talkers.length} unique`;
    const maxBytes = Math.max(...talkers.map(t => t.bytes));

    container.innerHTML = talkers.slice(0, 5).map((t, i) => {
        const kb = (t.bytes / 1024).toFixed(1);
        const pct = maxBytes > 0 ? ((t.bytes / maxBytes) * 100).toFixed(0) : 0;
        const rank = String(i + 1).padStart(2, '0');
        return `<div class="host-row">
            <div class="host-row-top">
                <span class="host-rank">#${rank}</span>
                <span class="host-ip">${t.ip}</span>
                <span class="host-meta"><span class="bold">${kb} KB</span> / ${t.packets || '--'} pkts</span>
            </div>
            <div class="host-bar"><div class="host-bar-fill" style="width:${pct}%"></div></div>
        </div>`;
    }).join('');
}

function updateHeaderAlertBadge() {
    const badge = document.getElementById('header-alert-badge');
    const count = document.getElementById('header-alert-count');
    if (!badge || !count) return;
    if (allAlerts.length > 0) {
        badge.classList.remove('hidden');
        count.textContent = `${allAlerts.length} alert${allAlerts.length !== 1 ? 's' : ''}`;
    } else {
        badge.classList.add('hidden');
    }
}

// =============================================================================
// 5. Packet Inspector
// =============================================================================
function handleNewPacket(pkt) {
    packetCounter++;
    pkt._num = packetCounter;
    packetBuffer.unshift(pkt);
    if (packetBuffer.length > 150) packetBuffer.pop();
    if (!isStreamPaused) renderPacketRow(pkt, true);
}

function renderPacketRow(pkt, isPrepend) {
    if (packetProtoFilter !== 'ALL' && pkt.proto !== packetProtoFilter) return;
    const query = (document.getElementById('packet-search').value || '').toLowerCase();
    if (query) {
        const str = `${pkt.src_ip} ${pkt.dst_ip} ${pkt.src_port} ${pkt.dst_port} ${pkt.proto} ${pkt.info}`.toLowerCase();
        if (!str.includes(query)) return;
    }

    const tbody = document.getElementById('packet-stream-body');
    const empty = tbody.querySelector('.empty-row');
    if (empty) empty.remove();

    const tr = document.createElement('tr');
    tr.id = `pkt-${pkt._num}`;

    const cells = [
        pkt._num,
        new Date(pkt.ts * 1000).toLocaleTimeString([], { hour12: false, fractionalSecondDigits: 3 }),
        pkt.src_port ? `${pkt.src_ip}:${pkt.src_port}` : pkt.src_ip,
        pkt.dst_port ? `${pkt.dst_ip}:${pkt.dst_port}` : pkt.dst_ip,
    ];

    cells.forEach(text => { const td = document.createElement('td'); td.textContent = text; tr.appendChild(td); });

    const tdProto = document.createElement('td');
    const span = document.createElement('span');
    span.className = `tag ${pkt.proto === 'TCP' ? 'tag-low' : pkt.proto === 'ICMP' ? 'tag-medium' : 'tag-high'}`;
    span.textContent = pkt.proto;
    tdProto.appendChild(span);
    tr.appendChild(tdProto);

    [
        `${pkt.length} B`,
        pkt.ttl !== null && pkt.ttl !== undefined ? pkt.ttl : '--',
        pkt.info || (pkt.tcp_flags ? `Flags [${pkt.tcp_flags}]` : '--'),
    ].forEach(text => { const td = document.createElement('td'); td.textContent = text; tr.appendChild(td); });

    const tdAction = document.createElement('td');
    const btn = document.createElement('button');
    btn.className = 'btn-inspect';
    btn.textContent = 'View';
    btn.onclick = () => openPacketModal(pkt);
    tdAction.appendChild(btn);
    tr.appendChild(tdAction);

    if (isPrepend && tbody.firstChild) tbody.insertBefore(tr, tbody.firstChild);
    else tbody.appendChild(tr);

    while (tbody.children.length > 100) tbody.removeChild(tbody.lastChild);
}

function togglePacketStream() {
    isStreamPaused = !isStreamPaused;
    const btn = document.getElementById('btn-stream-toggle');
    if (isStreamPaused) {
        btn.innerHTML = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="5 3 19 12 5 21 5 3"/></svg> Resume';
    } else {
        btn.innerHTML = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="6" y="4" width="4" height="16"/><rect x="14" y="4" width="4" height="16"/></svg> Pause';
    }
}

function clearPacketBuffer() {
    packetBuffer = [];
    document.getElementById('packet-stream-body').innerHTML = '<tr class="empty-row"><td colspan="9">Buffer cleared. Stream is active.</td></tr>';
}

function setPacketProtoFilter(proto) {
    packetProtoFilter = proto;
    document.querySelectorAll('.pill').forEach(p => {
        p.classList.toggle('active', p.textContent === proto || (proto === 'ALL' && p.textContent === 'All'));
    });
    filterPacketTable();
}

function filterPacketTable() {
    const tbody = document.getElementById('packet-stream-body');
    tbody.innerHTML = '';
    const filtered = packetBuffer.filter(pkt => {
        if (packetProtoFilter !== 'ALL' && pkt.proto !== packetProtoFilter) return false;
        const query = (document.getElementById('packet-search').value || '').toLowerCase();
        if (!query) return true;
        return `${pkt.src_ip} ${pkt.dst_ip} ${pkt.src_port} ${pkt.dst_port} ${pkt.proto} ${pkt.info}`.toLowerCase().includes(query);
    });
    if (filtered.length === 0) {
        tbody.innerHTML = '<tr class="empty-row"><td colspan="9">No packets match filter.</td></tr>';
        return;
    }
    filtered.forEach(p => renderPacketRow(p, false));
}

function openPacketModal(pkt) {
    document.getElementById('dissect-iface').textContent = pkt.iface || 'en0';
    document.getElementById('dissect-len').textContent = pkt.length;
    document.getElementById('dissect-ipver').textContent = pkt.ip_ver || 4;
    document.getElementById('dissect-srcip').textContent = pkt.src_ip;
    document.getElementById('dissect-dstip').textContent = pkt.dst_ip;
    document.getElementById('dissect-ttl').textContent = pkt.ttl !== null ? pkt.ttl : '64 (default)';
    document.getElementById('dissect-proto').textContent = pkt.proto;

    const l4 = document.getElementById('dissect-l4-node');
    if (pkt.proto === 'TCP' || pkt.proto === 'UDP') {
        l4.style.display = 'block';
        document.getElementById('dissect-l4-proto').textContent = pkt.proto;
        document.getElementById('dissect-sport').textContent = pkt.src_port || '--';
        document.getElementById('dissect-dport').textContent = pkt.dst_port || '--';
        if (pkt.proto === 'TCP') {
            document.getElementById('dissect-flags').textContent = pkt.tcp_flags || 'None';
            document.getElementById('dissect-seq').textContent = pkt.seq !== null ? pkt.seq : '--';
            document.getElementById('dissect-ack').textContent = pkt.ack !== null ? pkt.ack : '--';
            document.getElementById('dissect-win').textContent = pkt.window !== null ? pkt.window : '65535';
        } else {
            document.getElementById('dissect-flags').textContent = 'N/A';
            document.getElementById('dissect-seq').textContent = 'N/A';
            document.getElementById('dissect-ack').textContent = 'N/A';
            document.getElementById('dissect-win').textContent = 'N/A';
        }
    } else {
        l4.style.display = 'none';
    }
    document.getElementById('packet-dissector-modal').classList.remove('hidden');
}

function closePacketModal() { document.getElementById('packet-dissector-modal').classList.add('hidden'); }

// =============================================================================
// 6. TCP Connection Tracker
// =============================================================================
async function refreshConnections() {
    try {
        const res = await fetch('/api/connections');
        if (!res.ok) return;
        const data = await res.json();
        const flows = data.flows || [];
        const tbody = document.getElementById('connections-body');
        tbody.innerHTML = '';

        let halfOpen = 0;
        flows.forEach(f => { if (f.state === 'HALF_OPEN') halfOpen++; });
        document.getElementById('kpi-half-open').textContent = `${halfOpen} half-open`;
        document.getElementById('kpi-flows').textContent = flows.length;

        if (flows.length === 0) {
            tbody.innerHTML = '<tr class="empty-row"><td colspan="8">No active TCP connections currently tracked.</td></tr>';
            return;
        }

        flows.forEach(f => {
            const tr = document.createElement('tr');
            const cells = [
                f.flow_id,
                `${f.src_ip}:${f.src_port}`,
                `${f.dst_ip}:${f.dst_port}`,
            ];
            cells.forEach(t => { const td = document.createElement('td'); td.textContent = t; tr.appendChild(td); });

            const tdState = document.createElement('td');
            const s = document.createElement('span');
            s.className = `tag-state ${f.state.toLowerCase()}`;
            s.textContent = f.state;
            tdState.appendChild(s);
            tr.appendChild(tdState);

            [`${f.duration_s}s`, f.packet_count, `${(f.byte_count/1024).toFixed(1)} KB`,
             new Date(f.last_seen*1000).toLocaleTimeString([],{hour12:false})
            ].forEach(t => { const td = document.createElement('td'); td.textContent = t; tr.appendChild(td); });

            tbody.appendChild(tr);
        });
    } catch (err) { console.error("Connections load error:", err); }
}

// =============================================================================
// 7. Security Alert Feed
// =============================================================================
function handleNewAlert(alert) {
    allAlerts.unshift(alert);
    updateAlertStats();
    updateHeaderAlertBadge();
    renderAlertRow(alert, true);
    showToast(`[${alert.severity}] ${alert.type} from ${alert.src_ip}`, 'danger');
}

function updateAlertStats() {
    const total = allAlerts.length;
    const critical = allAlerts.filter(a => a.severity === 'CRITICAL' || a.severity === 'HIGH').length;
    document.getElementById('kpi-alerts-count').textContent = total;
    document.getElementById('kpi-critical-count').textContent = `${critical} high / critical`;
    document.getElementById('alerts-table-badge').textContent = `${total} events recorded`;

    const alertDelta = document.getElementById('kpi-alert-delta');
    if (alertDelta) {
        if (total > 0) {
            alertDelta.style.display = '';
            alertDelta.textContent = `+${total}`;
        } else {
            alertDelta.style.display = 'none';
        }
    }
}

function renderAlertRow(alert, isPrepend) {
    const tbody = document.getElementById('alerts-body');
    const empty = tbody.querySelector('.empty-row');
    if (empty) empty.remove();
    if (activeFilter !== 'ALL' && alert.severity !== activeFilter) return;

    const tr = document.createElement('tr');
    tr.id = `alert-${alert.id}`;

    const tdTime = document.createElement('td');
    tdTime.textContent = new Date(alert.ts * 1000).toLocaleTimeString([], { hour12: false });
    tr.appendChild(tdTime);

    const tdSev = document.createElement('td');
    const sev = document.createElement('span');
    sev.className = `tag tag-${alert.severity.toLowerCase()}`;
    sev.textContent = alert.severity;
    tdSev.appendChild(sev);
    tr.appendChild(tdSev);

    const tdType = document.createElement('td');
    tdType.innerHTML = `<strong>${alert.type}</strong>`;
    tr.appendChild(tdType);

    const tdSrc = document.createElement('td');
    tdSrc.innerHTML = `<code class="ip-pill source">${alert.src_ip || 'unknown'}</code>`;
    tr.appendChild(tdSrc);

    const tdDst = document.createElement('td');
    tdDst.innerHTML = `<code class="ip-pill">${alert.dst_ip || 'broadcast'}</code>`;
    tr.appendChild(tdDst);

    const tdSum = document.createElement('td');
    tdSum.textContent = alert.summary;
    tr.appendChild(tdSum);

    const tdAct = document.createElement('td');
    tdAct.style.display = 'flex';
    tdAct.style.gap = '4px';

    const btnBlock = document.createElement('button');
    btnBlock.className = 'btn-block';
    btnBlock.textContent = 'Block';
    btnBlock.onclick = (e) => { e.stopPropagation(); addToBlacklistDirect(alert.src_ip, `Blocked from alert: ${alert.type}`); };
    tdAct.appendChild(btnBlock);

    const btnInspect = document.createElement('button');
    btnInspect.className = 'btn-inspect';
    btnInspect.textContent = 'Inspect';
    btnInspect.onclick = () => openEvidenceModal(alert);
    tdAct.appendChild(btnInspect);

    tr.appendChild(tdAct);

    if (isPrepend && tbody.firstChild) tbody.insertBefore(tr, tbody.firstChild);
    else tbody.appendChild(tr);
}

function filterAlerts(severity) {
    activeFilter = severity;
    const tbody = document.getElementById('alerts-body');
    tbody.innerHTML = '';
    const filtered = activeFilter === 'ALL' ? allAlerts : allAlerts.filter(a => a.severity === activeFilter);
    if (filtered.length === 0) {
        tbody.innerHTML = `<tr class="empty-row"><td colspan="7">No events matching '${activeFilter}'.</td></tr>`;
        return;
    }
    filtered.forEach(a => renderAlertRow(a, false));
}

// =============================================================================
// 8. Rules Config
// =============================================================================
async function loadCurrentConfig() {
    try {
        const res = await fetch('/api/config');
        if (!res.ok) return;
        const data = await res.json();
        const r = data.rules || {};
        if (r.port_scan) { document.getElementById('cfg-port-threshold').value = r.port_scan.threshold || 15; document.getElementById('cfg-port-window').value = r.port_scan.window_s || 3.0; }
        if (r.syn_flood) { document.getElementById('cfg-syn-threshold').value = r.syn_flood.threshold || 50; document.getElementById('cfg-syn-ratio').value = r.syn_flood.ratio || 4.0; }
        if (r.rst_abuse) { document.getElementById('cfg-rst-threshold').value = r.rst_abuse.threshold || 10; document.getElementById('cfg-rst-window').value = r.rst_abuse.window_s || 5.0; }
    } catch (e) { console.error("Config load error:", e); }
}

async function applyConfigUpdates() {
    const payload = {
        port_scan_threshold: parseInt(document.getElementById('cfg-port-threshold').value),
        port_scan_window: parseFloat(document.getElementById('cfg-port-window').value),
        syn_threshold: parseInt(document.getElementById('cfg-syn-threshold').value),
        syn_ratio: parseFloat(document.getElementById('cfg-syn-ratio').value),
        rst_threshold: parseInt(document.getElementById('cfg-rst-threshold').value),
        rst_window: parseFloat(document.getElementById('cfg-rst-window').value),
    };
    try {
        const res = await fetch('/api/config', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify(payload) });
        showToast(res.ok ? "Detection thresholds updated." : "Failed to update config.", res.ok ? 'success' : 'danger');
    } catch (err) { showToast(`Config error: ${err.message}`, 'danger'); }
}

// =============================================================================
// 9. Initial Load & Attacks
// =============================================================================
async function fetchInitialData() {
    try {
        const healthRes = await fetch('/api/health');
        if (healthRes.ok) {
            const health = await healthRes.json();
            document.getElementById('iface-display').textContent = health.interface || 'en0';
        }
        const metricsRes = await fetch('/api/metrics/history');
        if (metricsRes.ok) {
            const data = await metricsRes.json();
            if (data.history && data.history.length > 0) data.history.forEach(m => handleMetricUpdate(m));
        }
        const alertsRes = await fetch('/api/alerts?limit=100');
        if (alertsRes.ok) {
            const data = await alertsRes.json();
            allAlerts = data.alerts || [];
            updateAlertStats();
            updateHeaderAlertBadge();
            const tbody = document.getElementById('alerts-body');
            tbody.innerHTML = '';
            if (allAlerts.length > 0) allAlerts.forEach(a => renderAlertRow(a, false));
        }
        const packetsRes = await fetch('/api/packets');
        if (packetsRes.ok) {
            const data = await packetsRes.json();
            if (data.packets) data.packets.forEach(p => handleNewPacket(p));
        }
    } catch (err) { console.error("Initial load error:", err); }
}

async function triggerAttack(attackType) {
    const statusEl = document.getElementById('attack-status');
    if (statusEl) statusEl.innerHTML = '<span class="status-dot" style="background:var(--amber)"></span> Running...';
    showToast(`Injecting: ${attackType.replace(/_/g, ' ')}...`, 'info');
    try {
        const res = await fetch('/api/simulate', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({ type: attackType }) });
        const data = await res.json();
        showToast(res.ok ? `'${attackType}' dispatched.` : `Error: ${data.error}`, res.ok ? 'success' : 'danger');
    } catch (err) { showToast(`Request failed: ${err.message}`, 'danger'); }
    setTimeout(() => {
        if (statusEl) statusEl.innerHTML = '<span class="status-dot"></span> Idle';
    }, 2000);
}

async function clearAlerts() {
    try {
        const res = await fetch('/api/alerts', { method: 'DELETE' });
        if (res.ok) {
            allAlerts = [];
            updateAlertStats();
            updateHeaderAlertBadge();
            document.getElementById('alerts-body').innerHTML = '<tr class="empty-row"><td colspan="7">No security events recorded.</td></tr>';
            showToast("Alert log cleared.", "info");
        }
    } catch (err) { console.error(err); }
}

function openEvidenceModal(alert) {
    document.getElementById('modal-type').textContent = alert.type;
    const s = document.getElementById('modal-severity');
    s.className = `tag tag-${alert.severity.toLowerCase()}`;
    s.textContent = alert.severity;
    document.getElementById('modal-src').textContent = alert.src_ip;
    document.getElementById('modal-dst').textContent = alert.dst_ip;
    document.getElementById('modal-summary').textContent = alert.summary;
    document.getElementById('modal-json').querySelector('code').textContent = JSON.stringify(alert.evidence, null, 2);
    document.getElementById('evidence-modal').classList.remove('hidden');
}

function closeModal() { document.getElementById('evidence-modal').classList.add('hidden'); }

// =============================================================================
// Toast Notifications
// =============================================================================
function showToast(message, type) {
    const container = document.getElementById('toast-container');
    const toast = document.createElement('div');
    toast.className = `toast toast-${type || 'info'}`;
    toast.textContent = message;
    container.appendChild(toast);
    setTimeout(() => { if (toast.parentNode) toast.remove(); }, 4200);
}

// =============================================================================
// Uptime & UTC Clock
// =============================================================================
let secondsUptime = 0;
function updateUptime() {
    secondsUptime++;
    const h = String(Math.floor(secondsUptime / 3600)).padStart(2, '0');
    const m = String(Math.floor((secondsUptime % 3600) / 60)).padStart(2, '0');
    const s = String(secondsUptime % 60).padStart(2, '0');
    document.getElementById('uptime-display').textContent = `${h}:${m}:${s}`;
}

function updateUTCClock() {
    const now = new Date();
    const utc = now.toUTCString().slice(-12, -4);
    const el = document.getElementById('utc-clock');
    if (el) el.textContent = utc;
}

// =============================================================================
// 10. Threat Map
// =============================================================================
let threatMap = null;
let threatMarkers = [];

function initThreatMap() {
    if (threatMap) return;
    const container = document.getElementById('threat-map');
    if (!container) return;

    threatMap = L.map('threat-map', { center: [20, 0], zoom: 2, minZoom: 2, maxZoom: 10 });

    L.tileLayer('https://tile.openstreetmap.org/{z}/{x}/{y}.png', {
        attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a>',
        maxZoom: 19,
        className: 'dark-tiles',
    }).addTo(threatMap);
}

async function refreshThreatMap() {
    initThreatMap();
    try {
        const res = await fetch('/api/geo/attackers');
        if (!res.ok) return;
        const data = await res.json();
        const locations = data.locations || [];

        threatMarkers.forEach(m => threatMap.removeLayer(m));
        threatMarkers = [];

        const tbody = document.getElementById('geo-table-body');
        tbody.innerHTML = '';

        if (locations.length === 0) {
            tbody.innerHTML = '<tr class="empty-row"><td colspan="8">No attacker locations available. Trigger an attack first.</td></tr>';
            return;
        }

        const sevColors = { CRITICAL: '#ef4444', HIGH: '#f97316', MEDIUM: '#eab308', LOW: '#3b82f6' };

        locations.forEach(loc => {
            const color = sevColors[loc.last_severity] || '#3b82f6';
            const marker = L.circleMarker([loc.lat, loc.lon], {
                radius: Math.min(6 + loc.alert_count * 2, 18),
                fillColor: color, color: color, weight: 2, opacity: 0.9, fillOpacity: 0.5,
            }).addTo(threatMap);

            marker.bindPopup(
                `<div style="font-family:sans-serif;font-size:13px;">` +
                `<strong>${loc.ip}</strong><br>${loc.city}, ${loc.country}<br>` +
                `Org: ${loc.org || 'Unknown'}<br>` +
                `Alerts: ${loc.alert_count} | ${loc.last_type}<br>` +
                `Severity: <span style="color:${color};font-weight:bold">${loc.last_severity}</span></div>`
            );
            threatMarkers.push(marker);

            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td><code class="ip-pill source">${loc.ip}</code></td>
                <td>${loc.city || '--'}</td>
                <td>${loc.country || '--'}</td>
                <td>${loc.org || 'Unknown'}</td>
                <td>${loc.alert_count}</td>
                <td>${loc.last_type}</td>
                <td><span class="tag tag-${loc.last_severity.toLowerCase()}">${loc.last_severity}</span></td>
                <td><button class="btn-block" onclick="blockFromMap('${loc.ip}')">Block</button></td>
            `;
            tbody.appendChild(tr);
        });

        if (locations.length > 0) {
            threatMap.fitBounds(L.latLngBounds(locations.map(l => [l.lat, l.lon])), { padding: [30,30], maxZoom: 5 });
        }
    } catch (err) { console.error("Threat map error:", err); }
}

function blockFromMap(ip) { addToBlacklistDirect(ip, 'Blocked from Threat Map'); }

// =============================================================================
// 11. IP Blacklist
// =============================================================================
async function loadBlacklist() {
    try {
        const res = await fetch('/api/blacklist');
        if (!res.ok) return;
        const data = await res.json();
        const entries = data.blacklist || [];
        const tbody = document.getElementById('blacklist-body');
        tbody.innerHTML = '';
        if (entries.length === 0) {
            tbody.innerHTML = '<tr class="empty-row"><td colspan="4">No IPs blacklisted yet.</td></tr>';
            return;
        }
        entries.forEach(e => {
            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td><code class="ip-pill source">${e.ip}</code></td>
                <td>${e.reason || '--'}</td>
                <td>${e.added_at || '--'}</td>
                <td><button class="btn-inspect" onclick="removeFromBlacklist('${e.ip}')">Unblock</button></td>
            `;
            tbody.appendChild(tr);
        });
    } catch (err) { console.error("Blacklist load error:", err); }
}

async function addToBlacklist() {
    const ip = document.getElementById('blacklist-ip-input').value.trim();
    const reason = document.getElementById('blacklist-reason-input').value.trim();
    if (!ip) { showToast('Enter an IP address.', 'danger'); return; }
    await addToBlacklistDirect(ip, reason || 'Manually blocked');
    document.getElementById('blacklist-ip-input').value = '';
    document.getElementById('blacklist-reason-input').value = '';
}

async function addToBlacklistDirect(ip, reason) {
    try {
        const res = await fetch('/api/blacklist', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ip, reason}) });
        if (res.ok) { showToast(`${ip} blocked.`, 'success'); loadBlacklist(); }
    } catch (err) { showToast(`Block failed: ${err.message}`, 'danger'); }
}

async function removeFromBlacklist(ip) {
    try {
        const res = await fetch('/api/blacklist', { method:'DELETE', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ip}) });
        if (res.ok) { showToast(`${ip} unblocked.`, 'info'); loadBlacklist(); }
    } catch (err) { showToast(`Unblock failed: ${err.message}`, 'danger'); }
}

// =============================================================================
// 12. Email Settings
// =============================================================================
async function loadEmailSettings() {
    try {
        const res = await fetch('/api/settings/email');
        if (!res.ok) return;
        const d = await res.json();
        document.getElementById('email-enabled').value = d.enabled ? 'true' : 'false';
        document.getElementById('email-recipient').value = d.recipient_email || '';
        document.getElementById('email-smtp-host').value = d.smtp_host || 'smtp.gmail.com';
        document.getElementById('email-smtp-port').value = d.smtp_port || 587;
        document.getElementById('email-sender').value = d.sender_email || '';
        document.getElementById('email-min-severity').value = d.min_severity || 'HIGH';
    } catch (err) { console.error("Email settings error:", err); }
}

async function saveEmailSettings() {
    const payload = {
        enabled: document.getElementById('email-enabled').value === 'true',
        recipient_email: document.getElementById('email-recipient').value,
        smtp_host: document.getElementById('email-smtp-host').value,
        smtp_port: parseInt(document.getElementById('email-smtp-port').value),
        sender_email: document.getElementById('email-sender').value,
        sender_password: document.getElementById('email-password').value,
        min_severity: document.getElementById('email-min-severity').value,
    };
    try {
        const res = await fetch('/api/settings/email', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(payload) });
        showToast(res.ok ? 'Email settings saved.' : 'Failed to save.', res.ok ? 'success' : 'danger');
    } catch (err) { showToast(`Error: ${err.message}`, 'danger'); }
}
