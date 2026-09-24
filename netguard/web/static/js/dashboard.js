/**
 * NetGuard Enterprise SOC Dashboard Client Script
 * Implements 3 modular workspaces, dual-axis Chart.js telemetry,
 * real-time heuristic diagnostic interpretation, timezone switching,
 * stateful forensics, and educational incident analysis.
 */

let socket = null;
let bandwidthChart = null;
let protocolChart = null;
let maxChartPoints = 60;
let peakPpsRecorded = 0;

let allAlerts = [];
let activeFilter = "ALL";

let packetBuffer = [];
let packetCounter = 0;
let isStreamPaused = false;
let packetProtoFilter = "ALL";

let threatMap = null;
let threatMarkers = [];

// Timezone preference (saved to localStorage)
let currentTimezone = localStorage.getItem("netguard_tz") || "UTC";

document.addEventListener("DOMContentLoaded", () => {
    initTimezone();
    initCharts();
    initSocketIO();
    fetchInitialData();
    refreshConnections();
    refreshDevices();
    setInterval(updateLiveClocks, 1000);
    setInterval(refreshConnections, 3000);
    setInterval(refreshDevices, 6000);
    setTimeout(initPipelineAnimation, 500);

    // Auto-launch guided tour on first visit if not yet dismissed
    if (!localStorage.getItem("netguard_tour_dismissed")) {
        setTimeout(startGuidedTour, 400);
    }
});

// =============================================================================
// 1. Timezone Management (UTC vs Local)
// =============================================================================
function initTimezone() {
    setTimezone(currentTimezone, false);
}

function setTimezone(tz, updateTables = true) {
    currentTimezone = tz;
    localStorage.setItem("netguard_tz", tz);

    const btnUtc = document.getElementById("tz-btn-utc");
    const btnLocal = document.getElementById("tz-btn-local");
    if (btnUtc && btnLocal) {
        btnUtc.classList.toggle("active", tz === "UTC");
        btnLocal.classList.toggle("active", tz === "LOCAL");
    }

    updateLiveClocks();

    if (updateTables) {
        filterAlerts(activeFilter);
        filterPacketTable();
        refreshConnections();
        showToast(`Timezone switched to ${tz === "UTC" ? "UTC (GMT)" : "Local Browser Time"}`, "info");
    }
}

function formatTimestamp(epochSec, includeSeconds = true) {
    if (!epochSec) return "--:--:--";
    const d = new Date(epochSec * 1000);
    if (currentTimezone === "UTC") {
        const hh = String(d.getUTCHours()).padStart(2, "0");
        const mm = String(d.getUTCMinutes()).padStart(2, "0");
        const ss = String(d.getUTCSeconds()).padStart(2, "0");
        return includeSeconds ? `${hh}:${mm}:${ss} UTC` : `${hh}:${mm} UTC`;
    } else {
        const hh = String(d.getHours()).padStart(2, "0");
        const mm = String(d.getMinutes()).padStart(2, "0");
        const ss = String(d.getSeconds()).padStart(2, "0");
        return includeSeconds ? `${hh}:${mm}:${ss}` : `${hh}:${mm}`;
    }
}

function updateLiveClocks() {
    const clockEl = document.getElementById("live-clock");
    if (clockEl) {
        const now = Date.now() / 1000;
        clockEl.textContent = formatTimestamp(now, true);
    }
    updateUptime();
}

let startUptimeTimestamp = Date.now();
function updateUptime() {
    const diff = Math.floor((Date.now() - startUptimeTimestamp) / 1000);
    const h = String(Math.floor(diff / 3600)).padStart(2, "0");
    const m = String(Math.floor((diff % 3600) / 60)).padStart(2, "0");
    const s = String(diff % 60).padStart(2, "0");
    const el = document.getElementById("uptime-display");
    if (el) el.textContent = `${h}:${m}:${s}`;
}

// =============================================================================
// 2. Workspace & Tab Navigation
// =============================================================================
function switchTab(tabName, btnEl) {
    // Synchronize sidebar nav items
    document.querySelectorAll(".sidebar-nav .nav-item").forEach(b => b.classList.remove("active"));
    const sideBtn = document.getElementById(`nav-${tabName}`) || btnEl;
    if (sideBtn) sideBtn.classList.add("active");

    // Synchronize top workspace tabs
    document.querySelectorAll(".workspace-tabs .workspace-tab").forEach(tab => {
        const match = tab.getAttribute("onclick") && tab.getAttribute("onclick").includes(tabName);
        tab.classList.toggle("active", match);
    });

    // Switch tab pane
    document.querySelectorAll(".tab-pane").forEach(p => p.classList.remove("active"));
    const pane = document.getElementById(`tab-${tabName}`);
    if (pane) pane.classList.add("active");

    document.getElementById("sidebar").classList.remove("open");

    // Specific workspace initializations
    if (tabName === "threats") {
        setTimeout(() => {
            initThreatMap();
            if (threatMap) threatMap.invalidateSize();
            refreshThreatMap();
        }, 150);
    } else if (tabName === "forensics") {
        refreshDevices();
        refreshConnections();
    } else if (tabName === "config") {
        loadCurrentConfig();
        loadEmailSettings();
    }
}

function switchForensicSubtab(subName, btnEl) {
    document.querySelectorAll(".forensics-tab-btn").forEach(b => b.classList.remove("active"));
    if (btnEl) btnEl.classList.add("active");

    document.querySelectorAll(".forensics-subpane").forEach(p => p.style.display = "none");
    const pane = document.getElementById(`subpane-${subName}`);
    if (pane) pane.style.display = "block";

    if (subName === "devices") refreshDevices();
    else if (subName === "connections") refreshConnections();
}

function toggleSidebar() {
    document.getElementById("sidebar").classList.toggle("open");
}

// =============================================================================
// 3. Dual-Axis Chart.js Telemetry
// =============================================================================
function initCharts() {
    Chart.defaults.color = "#94a3b8";
    Chart.defaults.borderColor = "#1e293b";
    Chart.defaults.font.family = "'Geist', sans-serif";

    // Dual-Axis Throughput (KB/s) & Packet Rate (PPS)
    const bwCanvas = document.getElementById("bandwidthChart");
    if (bwCanvas) {
        const bwCtx = bwCanvas.getContext("2d");
        const gradient = bwCtx.createLinearGradient(0, 0, 0, 220);
        gradient.addColorStop(0, "rgba(56, 189, 248, 0.22)");
        gradient.addColorStop(1, "rgba(56, 189, 248, 0.01)");

        bandwidthChart = new Chart(bwCtx, {
            type: "line",
            data: {
                labels: [],
                datasets: [
                    {
                        label: "Bandwidth (KB/s)",
                        data: [],
                        borderColor: "#38bdf8",
                        backgroundColor: gradient,
                        fill: true,
                        tension: 0.35,
                        borderWidth: 2,
                        yAxisID: "yBandwidth",
                        pointRadius: 0,
                    },
                    {
                        label: "Packet Rate (PPS)",
                        data: [],
                        borderColor: "#f59e0b",
                        backgroundColor: "transparent",
                        fill: false,
                        tension: 0.35,
                        borderWidth: 1.5,
                        yAxisID: "yPPS",
                        pointRadius: 0,
                        borderDash: [4, 3],
                    },
                    {
                        label: "Baseline Corridor (μ + 2σ)",
                        data: [],
                        borderColor: "rgba(244, 63, 94, 0.5)",
                        backgroundColor: "transparent",
                        fill: false,
                        tension: 0.35,
                        borderWidth: 1.2,
                        yAxisID: "yPPS",
                        pointRadius: 0,
                        borderDash: [5, 4],
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                animation: false,
                interaction: {
                    mode: "index",
                    intersect: false,
                },
                scales: {
                    x: {
                        grid: { color: "rgba(30, 41, 59, 0.6)" },
                        ticks: {
                            maxTicksLimit: 8,
                            font: { size: 10, family: "'JetBrains Mono', monospace" }
                        }
                    },
                    yBandwidth: {
                        type: "linear",
                        position: "left",
                        beginAtZero: true,
                        grid: { color: "rgba(30, 41, 59, 0.6)" },
                        title: { display: true, text: "Throughput (KB/s)", font: { size: 10 } },
                        ticks: { font: { size: 10, family: "'JetBrains Mono', monospace" } }
                    },
                    yPPS: {
                        type: "linear",
                        position: "right",
                        beginAtZero: true,
                        grid: { drawOnChartArea: false },
                        title: { display: true, text: "Packets / sec", font: { size: 10 } },
                        ticks: { font: { size: 10, family: "'JetBrains Mono', monospace" } }
                    }
                },
                plugins: {
                    legend: {
                        labels: {
                            boxWidth: 10,
                            font: { size: 11, weight: "500" },
                            padding: 12
                        }
                    },
                    tooltip: {
                        backgroundColor: "#0f172a",
                        borderColor: "#334155",
                        borderWidth: 1,
                        titleFont: { family: "'JetBrains Mono', monospace", size: 11 },
                        bodyFont: { family: "'Geist', sans-serif", size: 12 },
                        padding: 10,
                        callbacks: {
                            afterBody: function(context) {
                                const kb = context[0]?.parsed?.y || 0;
                                const pps = context[1]?.parsed?.y || 0;
                                const avgBytes = pps > 0 ? Math.round((kb * 1024) / pps) : 0;
                                return `Avg Packet Size: ${avgBytes} Bytes`;
                            }
                        }
                    }
                }
            }
        });
    }

    // Protocol Distribution Doughnut
    const protoCanvas = document.getElementById("protocolChart");
    if (protoCanvas) {
        const protoCtx = protoCanvas.getContext("2d");
        protocolChart = new Chart(protoCtx, {
            type: "doughnut",
            data: {
                labels: ["TCP (Web/Apps)", "UDP (DNS/Media)", "ICMP (Diagnostics)", "Other"],
                datasets: [{
                    data: [0, 0, 0, 0],
                    backgroundColor: ["#38bdf8", "#818cf8", "#fbbf24", "#64748b"],
                    borderColor: "#111827",
                    borderWidth: 3,
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                cutout: "70%",
                plugins: {
                    legend: {
                        position: "bottom",
                        labels: { boxWidth: 10, padding: 8, font: { size: 10 } }
                    }
                }
            }
        });
    }
}

function setChartRange(seconds) {
    maxChartPoints = seconds;
    document.querySelectorAll(".btn-chart-range").forEach(b => {
        b.classList.toggle("active", b.textContent.includes(seconds === 60 ? "60s" : "5m"));
    });
    if (bandwidthChart) {
        const labels = bandwidthChart.data.labels;
        const kbData = bandwidthChart.data.datasets[0].data;
        const ppsData = bandwidthChart.data.datasets[1].data;
        const baseData = bandwidthChart.data.datasets[2]?.data;
        while (labels.length > maxChartPoints) {
            labels.shift();
            kbData.shift();
            ppsData.shift();
            if (baseData) baseData.shift();
        }
        bandwidthChart.update("none");
    }
}

// =============================================================================
// 4. WebSocket & Real-Time Ingress Telemetry
// =============================================================================
function initSocketIO() {
    socket = io();
    const dot = document.getElementById("status-dot");
    const statusText = document.getElementById("connection-status");

    socket.on("connect", () => {
        if (dot) dot.classList.remove("disconnected");
        if (statusText) statusText.textContent = "Engine Connected";
    });
    socket.on("disconnect", () => {
        if (dot) dot.classList.add("disconnected");
        if (statusText) statusText.textContent = "Offline";
    });
    socket.on("metrics", (data) => { handleMetricUpdate(data); });
    socket.on("alert", (alert) => { handleNewAlert(alert); });
    socket.on("packet", (pkt) => { handleNewPacket(pkt); });
}

function handleMetricUpdate(m) {
    // Ingress Totals
    const totPacketsEl = document.getElementById("kpi-total-packets");
    if (totPacketsEl) totPacketsEl.textContent = m.total_packets.toLocaleString();

    const totVolEl = document.getElementById("kpi-total-volume");
    if (totVolEl) {
        const kb = m.total_bytes / 1024;
        totVolEl.textContent = kb > 1024 ? `${(kb / 1024).toFixed(2)} MB captured` : `${kb.toFixed(1)} KB captured`;
    }

    const ppsEl = document.getElementById("kpi-pps-delta");
    if (ppsEl) ppsEl.textContent = `+${m.pps} pps`;

    // Throughput
    const kbPerSec = (m.bps / 1024).toFixed(1);
    const tpEl = document.getElementById("kpi-throughput");
    if (tpEl) tpEl.innerHTML = `${kbPerSec} <span class="unit">KB/s</span>`;

    const kbpsEl = document.getElementById("kpi-kbps");
    if (kbpsEl) kbpsEl.textContent = `${m.kbps} Kbps`;

    // Average Packet Size
    const avgSize = m.avg_packet_size || (m.pps > 0 ? Math.round(m.bps / m.pps) : 0);
    const avgSizeEl = document.getElementById("kpi-avg-size");
    if (avgSizeEl) avgSizeEl.innerHTML = `${avgSize} <span class="unit">Bytes</span>`;

    const sizeCatEl = document.getElementById("kpi-size-category");
    const sizeDeltaEl = document.getElementById("kpi-size-delta");
    if (sizeCatEl) {
        if (avgSize < 90 && m.pps > 30) {
            sizeCatEl.textContent = "Tiny (Probe/SYN flood)";
            if (sizeDeltaEl) { sizeDeltaEl.textContent = "Anomalous"; sizeDeltaEl.style.color = "#f87171"; }
        } else if (avgSize > 800) {
            sizeCatEl.textContent = "Bulk Payload Stream";
            if (sizeDeltaEl) { sizeDeltaEl.textContent = "Bulk"; sizeDeltaEl.style.color = "#38bdf8"; }
        } else {
            sizeCatEl.textContent = "Balanced Payload";
            if (sizeDeltaEl) { sizeDeltaEl.textContent = "Normal"; sizeDeltaEl.style.color = "#34d399"; }
        }
    }

    // Sub-KPIs
    const subPps = document.getElementById("sub-pps");
    if (subPps) subPps.textContent = m.pps;

    const subAvg = document.getElementById("sub-avg-size");
    if (subAvg) subAvg.textContent = `${avgSize} B`;

    const subDrops = document.getElementById("sub-drops");
    if (subDrops) subDrops.textContent = m.drop_count || 0;

    const kpiFlows = document.getElementById("kpi-flows");
    if (kpiFlows && m.active_flows_count !== undefined) kpiFlows.textContent = m.active_flows_count;

    // Peak PPS tracking
    if (m.pps > peakPpsRecorded) {
        peakPpsRecorded = m.pps;
        const peakEl = document.getElementById("chart-pps-stat");
        if (peakEl) peakEl.textContent = `Peak: ${peakPpsRecorded} pps`;
    }

    // Pipeline PPS badge
    const pipelinePps = document.getElementById("pipeline-pps");
    if (pipelinePps) pipelinePps.textContent = `${m.pps} pps`;

    // Diagnostic Interpretation Banner
    updateDiagnosticBanner(m, avgSize);

    // Update Chart.js Timeline
    if (bandwidthChart) {
        const timeLabel = formatTimestamp(m.ts, true);
        const labels = bandwidthChart.data.labels;
        const kbData = bandwidthChart.data.datasets[0].data;
        const ppsData = bandwidthChart.data.datasets[1].data;

        const upperPps = m.baseline_upper_pps || Math.round(m.pps * 1.5 + 20);
        labels.push(timeLabel);
        kbData.push(parseFloat(kbPerSec));
        ppsData.push(m.pps);
        const baseData = bandwidthChart.data.datasets[2]?.data;
        if (baseData) baseData.push(upperPps);

        while (labels.length > maxChartPoints) {
            labels.shift();
            kbData.shift();
            ppsData.shift();
            if (baseData) baseData.shift();
        }
        bandwidthChart.update("none");
    }

    // Protocol Chart Update
    if (protocolChart && m.protocol_counts) {
        protocolChart.data.datasets[0].data = [
            m.protocol_counts["TCP"] || 0,
            m.protocol_counts["UDP"] || 0,
            m.protocol_counts["ICMP"] || 0,
            m.protocol_counts["OTHER"] || 0
        ];
        protocolChart.update("none");
    }

    // Top Talkers Leaderboard
    if (m.top_talkers) renderTopHosts(m.top_talkers);

    // Threat Gauge calculation
    updateThreatGauge(m);
}

function updateDiagnosticBanner(m, avgSize) {
    const banner = document.getElementById("diag-banner");
    const icon = document.getElementById("diag-icon");
    const title = document.getElementById("diag-title");
    const desc = document.getElementById("diag-desc");
    const chipAvg = document.getElementById("chip-avg-size");
    const chipPps = document.getElementById("chip-pps");
    const chipBw = document.getElementById("chip-bandwidth");

    if (chipAvg) chipAvg.textContent = `Avg Size: ${avgSize} B`;
    if (chipPps) chipPps.textContent = `PPS: ${m.pps}`;
    if (chipBw) chipBw.textContent = `Throughput: ${(m.bps / 1024).toFixed(1)} KB/s`;

    if (!banner || !icon || !title || !desc) return;

    banner.className = "diag-banner";
    if (m.pps > 60 && avgSize < 90) {
        banner.classList.add("danger");
        icon.textContent = "🚨";
        title.textContent = "Heuristic Anomaly: High-Rate Scan or SYN Flood";
        desc.textContent = `Massive burst of ${m.pps} packets/sec with tiny average packet size (${avgSize} bytes). Characteristic of TCP SYN flood or port sweep reconnaissance without application payload.`;
    } else if (m.protocol_counts && m.protocol_counts["UDP"] > 35) {
        banner.classList.add("warning");
        icon.textContent = "⚠️";
        title.textContent = "Volumetric Alert: UDP Amplification Surge";
        desc.textContent = `Unusual concentration of UDP ingress (${m.protocol_counts["UDP"]} pkts/s). Possible DNS reflection or UDP volumetric burst targeting open service ports.`;
    } else if (m.pps > 60 && avgSize > 700) {
        icon.textContent = "ℹ️";
        title.textContent = "Volumetric Stream: Bulk Payload Download";
        desc.textContent = `High packet rate with large average payload (${avgSize} bytes). Indicates legitimate bulk file transfer or video stream.`;
    } else {
        icon.textContent = "🟢";
        title.textContent = "Healthy Traffic Baseline";
        desc.textContent = "Packet rates and byte distributions are within expected operating parameters. Clean ingress.";
    }
}

function renderTopHosts(talkers) {
    const container = document.getElementById("top-hosts-list");
    const countBadge = document.getElementById("top-hosts-count");
    if (!container) return;

    if (!talkers || talkers.length === 0) {
        container.innerHTML = '<div style="text-align:center;color:var(--text-muted);padding:1.5rem;font-size:12px;">Monitoring stream... Active host traffic will rank here in real time.</div>';
        if (countBadge) countBadge.textContent = "0 active";
        return;
    }

    if (countBadge) countBadge.textContent = `${talkers.length} active`;
    const maxBytes = Math.max(...talkers.map(t => t.bytes));

    container.innerHTML = talkers.slice(0, 5).map((t, i) => {
        const kb = (t.bytes / 1024).toFixed(1);
        const pct = maxBytes > 0 ? ((t.bytes / maxBytes) * 100).toFixed(0) : 0;
        const rank = String(i + 1).padStart(2, "0");
        return `<div class="host-row">
            <div class="host-row-top">
                <span class="host-rank">#${rank}</span>
                <span class="host-ip">${t.ip}</span>
                <span class="host-meta"><span class="bold">${kb} KB</span> / ${t.packets || "--"} pkts</span>
            </div>
            <div class="host-bar"><div class="host-bar-fill" style="width:${pct}%"></div></div>
        </div>`;
    }).join("");
}

async function resetSessionMetrics() {
    try {
        const res = await fetch("/api/metrics/reset", { method: "POST" });
        if (res.ok) {
            peakPpsRecorded = 0;
            if (bandwidthChart) {
                bandwidthChart.data.labels = [];
                bandwidthChart.data.datasets[0].data = [];
                bandwidthChart.data.datasets[1].data = [];
                bandwidthChart.update();
            }
            document.getElementById("kpi-total-packets").textContent = "0";
            document.getElementById("kpi-total-volume").textContent = "0.0 KB captured";
            showToast("Session ingress counters reset successfully.", "success");
        }
    } catch (err) {
        console.error("Reset metrics error:", err);
    }
}

// =============================================================================
// 5. Threat Score & Alert Stats Aggregation
// =============================================================================
let lastMetrics = {};

function updateThreatGauge(metrics) {
    if (metrics) lastMetrics = metrics;
    const m = metrics || lastMetrics || {};

    const gaugeEl = document.getElementById("gauge-fill");
    const scoreEl = document.getElementById("threat-score");
    const statusEl = document.getElementById("threat-status");

    const kpiValEl = document.getElementById("kpi-threat-val");
    const kpiStatusEl = document.getElementById("kpi-threat-status");
    const kpiBarEl = document.getElementById("kpi-threat-bar");
    const kpiLabelEl = document.getElementById("threat-status-label");

    let score = 0;
    const pps = m.pps || 0;

    // PPS anomaly contribution (0-40 pts)
    if (pps > 120) score += 40;
    else if (pps > 60) score += Math.floor(((pps - 60) / 60) * 40);

    // Recent alerts contribution (0-60 pts)
    const now = Date.now() / 1000;
    const recent = allAlerts.filter(a => now - a.ts < 60);
    recent.forEach(a => {
        if (a.severity === "CRITICAL") score += 20;
        else if (a.severity === "HIGH") score += 10;
        else if (a.severity === "MEDIUM") score += 5;
    });

    score = Math.min(100, Math.max(0, score));

    // Status classification
    let statusText = "Normal";
    let statusClass = "emerald";
    let statusDesc = "Guarded ≤ 20";

    if (score >= 75) {
        statusText = "Critical";
        statusClass = "critical";
        statusDesc = "Hostile intrusion in progress";
    } else if (score >= 45) {
        statusText = "Elevated";
        statusClass = "danger";
        statusDesc = "Anomalous flood volume";
    } else if (score >= 20) {
        statusText = "Guarded";
        statusClass = "warning";
        statusDesc = "Suspicious traffic detected";
    }

    // Header Gauge (if present)
    if (gaugeEl) {
        gaugeEl.setAttribute("stroke-dasharray", `${score}, 100`);
        gaugeEl.className = "gauge-fill";
        if (score >= 75) gaugeEl.classList.add("critical");
        else if (score >= 45) gaugeEl.classList.add("danger");
        else if (score >= 20) gaugeEl.classList.add("warning");
    }
    if (scoreEl) scoreEl.textContent = score;
    if (statusEl) {
        statusEl.className = `gauge-status ${statusClass}`;
        statusEl.textContent = statusText;
    }

    // Primary Dashboard KPI Card: Threat Level (0 to 100)
    if (kpiValEl) {
        const valClass = statusClass === "emerald" ? "emerald" : statusClass === "warning" ? "amber" : "rose";
        kpiValEl.innerHTML = `${score}<span class="unit"> / 100</span>`;
        kpiValEl.className = `kpi-value ${valClass}`;
    }
    if (kpiStatusEl) {
        kpiStatusEl.textContent = statusText;
        kpiStatusEl.className = `tag tag-${statusClass === "emerald" ? "normal" : statusClass}`;
    }
    if (kpiBarEl) {
        kpiBarEl.style.width = `${score}%`;
        const barClass = statusClass === "critical" || statusClass === "danger" ? "rose" : statusClass === "warning" ? "amber" : "emerald";
        kpiBarEl.className = `kpi-bar-fill ${barClass}`;
    }
    if (kpiLabelEl) {
        kpiLabelEl.textContent = statusDesc;
    }
}

function updateAlertStats() {
    const total = allAlerts.length;
    const critical = allAlerts.filter(a => a.severity === "CRITICAL" || a.severity === "HIGH").length;

    const countEl = document.getElementById("kpi-alerts-count");
    if (countEl) countEl.textContent = total;

    const critEl = document.getElementById("kpi-critical-count");
    if (critEl) critEl.textContent = `${critical} high / critical`;

    const deltaEl = document.getElementById("kpi-alert-delta");
    if (deltaEl) {
        if (total > 0) {
            deltaEl.style.display = "inline-block";
            deltaEl.textContent = `+${total}`;
        } else {
            deltaEl.style.display = "none";
        }
    }

    const tableBadge = document.getElementById("alerts-table-badge");
    if (tableBadge) tableBadge.textContent = `${total} security alerts recorded`;

    // Recalculate Threat Level (0 to 100) with the updated alert list
    updateThreatGauge(lastMetrics);
}

// =============================================================================
// 6. Packet Inspection Pipeline Animation
// =============================================================================
let pipelineParticles = [];
let pipelineAnimFrame = null;

function initPipelineAnimation() {
    const canvas = document.getElementById("pipeline-canvas");
    if (!canvas) return;
    const ctx = canvas.getContext("2d");

    function resize() {
        canvas.width = canvas.offsetWidth * (window.devicePixelRatio || 1);
        canvas.height = 70 * (window.devicePixelRatio || 1);
        ctx.scale(window.devicePixelRatio || 1, window.devicePixelRatio || 1);
    }
    resize();
    window.addEventListener("resize", resize);

    function animate() {
        const w = canvas.offsetWidth;
        const h = 70;
        ctx.clearRect(0, 0, w, h);

        // Backbone bus line
        ctx.strokeStyle = "#1e293b";
        ctx.lineWidth = 2;
        ctx.beginPath();
        ctx.moveTo(35, h / 2);
        ctx.lineTo(w - 35, h / 2);
        ctx.stroke();

        // 5 Stage Nodes
        const stageCount = 5;
        const spacing = (w - 70) / (stageCount - 1);
        for (let i = 0; i < stageCount; i++) {
            const x = 35 + i * spacing;
            ctx.beginPath();
            ctx.arc(x, h / 2, 5, 0, Math.PI * 2);
            ctx.fillStyle = "#0f172a";
            ctx.fill();
            ctx.strokeStyle = "#38bdf8";
            ctx.lineWidth = 1.5;
            ctx.stroke();
        }

        // Animated packet particles
        pipelineParticles = pipelineParticles.filter(p => p.x < w - 30);
        pipelineParticles.forEach(p => {
            p.x += p.speed;
            ctx.beginPath();
            ctx.arc(p.x, h / 2 + Math.sin(p.x * 0.08) * 3, 3, 0, Math.PI * 2);
            ctx.fillStyle = p.malicious ? "#ef4444" : "#10b981";
            ctx.globalAlpha = 0.85;
            ctx.fill();
            ctx.globalAlpha = 1.0;
        });

        pipelineAnimFrame = requestAnimationFrame(animate);
    }
    animate();
}

function addPipelineParticle(isMalicious) {
    pipelineParticles.push({
        x: 35,
        speed: 1.8 + Math.random() * 1.5,
        malicious: isMalicious,
    });
}

// =============================================================================
// 7. Security Alerts & Incident Explainer
// =============================================================================
const ATTACK_EXPLANATIONS = {
    PORT_SCAN: {
        what: "An attacker systematically probed multiple network ports on the target machine to discover running services. This is reconnaissance phase 1 of the Cyber Kill Chain.",
        trigger: "Detection engine observed 15+ unique destination ports probed from a single source IP within a sliding 3.0-second time window.",
        impact: "Exposes vulnerable exposed services (SSH, HTTP, Database) allowing the attacker to craft tailored zero-day or CVE exploits.",
        defense: "Deploy host-based firewall, drop unsolicited TCP SYNs silently, implement port knocking, and ban persistent scanners using fail2ban.",
    },
    SYN_FLOOD: {
        what: "A volumetric Denial of Service attack where the attacker sent high-volume TCP SYN packets without finishing the 3-way handshake, exhausting kernel state tables.",
        trigger: "Observed 50+ SYN packets with a SYN:SYN-ACK ratio exceeding 4.0:1 in the 2.0-second inspection window.",
        impact: "Saturates server backlog queues, causing web and database services to freeze and drop legitimate user connections.",
        defense: "Enable SYN Cookies (net.ipv4.tcp_syncookies = 1), lower SYN-RECEIVED timeouts, and configure upstream DDoS scrubbing.",
    },
    RST_ABUSE: {
        what: "An attacker injected unsolicited TCP RST (Reset) packets to abruptly terminate active encrypted sessions on sensitive ports like TLS (443) or SSH (22).",
        trigger: "Observed 10+ TCP RST packets targeted at protected services from a single source within a 5.0-second sliding window.",
        impact: "Tears down active user sessions, drops transactions, disrupts VPN tunnels, and denies legitimate session continuity.",
        defense: "Enforce authenticated encryption (TLS/IPsec), enable TCP MD5 signatures, and drop unsolicited RST packets at perimeter firewall.",
    },
    UDP_FLOOD: {
        what: "A volumetric flood targeting UDP ports (such as DNS 53). Often uses DNS reflection and amplification to multiply incoming flood bandwidth.",
        trigger: "Observed 40+ UDP datagrams targeting services within 3.0s exceeding normal connectionless threshold.",
        impact: "Saturates incoming link bandwidth, causing total network latency spikes and buffer drops across all applications.",
        defense: "Implement BCP 38 anti-spoofing ingress filtering, rate-limit UDP inbound at border router, and disable open DNS recursion.",
    },
    ICMP_FLOOD: {
        what: "A ping flood saturating network link capacity by bombarding target IP with continuous ICMP Echo Request packets.",
        trigger: "Observed 30+ ICMP datagrams within the sliding 3.0-second time window.",
        impact: "Consumes network bandwidth and CPU cycles as target tries to respond with ICMP Echo Replies.",
        defense: "Rate-limit ICMP echo requests in firewall and configure router to drop oversized ICMP fragments.",
    },
    DNS_TUNNELING: {
        what: "An attacker established a covert command-and-control (C2) channel or exfiltrated encoded database records using UDP port 53 DNS queries to bypass perimeter firewalls.",
        trigger: "Detection engine identified 15+ anomalous, oversized DNS queries (average payload > 90 bytes) targeting external nameservers in a 4.0s window.",
        impact: "Confidential data leakage (credentials, internal records, intellectual property) bypassing firewalls that only permit outbound DNS.",
        defense: "Deploy DNS-layer firewalls (RPZ/DNSSEC), enforce split-horizon DNS, inspect query entropy, and drop direct external UDP 53 egress.",
    }
};

function handleNewAlert(alert) {
    allAlerts.unshift(alert);
    updateAlertStats();
    renderAlertRow(alert, true);

    // Pulse red particles in pipeline
    for (let i = 0; i < 5; i++) {
        setTimeout(() => addPipelineParticle(true), i * 80);
    }

    showToast(`[${alert.severity}] ${alert.type} from ${alert.src_ip}`, "danger");
    refreshThreatMap();
}

function renderAlertRow(alert, isPrepend) {
    const tbody = document.getElementById("alerts-body");
    if (!tbody) return;

    const empty = tbody.querySelector(".empty-row");
    if (empty) empty.remove();

    const tr = document.createElement("tr");
    tr.className = "alert-new";

    const sevClass = alert.severity === "CRITICAL" ? "tag-critical" : alert.severity === "HIGH" ? "tag-high" : "tag-medium";
    const timeStr = formatTimestamp(alert.ts, true);

    tr.innerHTML = `
        <td style="font-family:var(--font-mono);font-size:11px;">${timeStr}</td>
        <td><span class="tag ${sevClass}">${alert.severity}</span></td>
        <td><strong style="color:#f1f5f9;">${alert.type}</strong></td>
        <td><code class="ip-pill source">${alert.src_ip}</code></td>
        <td><code class="ip-pill">${alert.dst_ip}</code></td>
        <td style="font-size:11px;color:var(--text-secondary);">${alert.summary}</td>
        <td>
            <button class="btn-inspect" onclick="openExplainModal('${alert.id}')" style="background:#1e293b;border-color:#38bdf8;color:#38bdf8;">Explain</button>
            <button class="btn-inspect" onclick="openEvidenceModal('${alert.id}')" style="margin-left:4px;">Evidence</button>
            <a href="/api/export/pcap/alert/${alert.id}" class="btn-pcap" download="incident_${(alert.id||'').slice(0,8)}.pcap" style="margin-left:4px;" title="Download PCAP of this specific incident">💾 PCAP</a>
        </td>
    `;

    if (isPrepend && tbody.firstChild) tbody.insertBefore(tr, tbody.firstChild);
    else tbody.appendChild(tr);

    const countBadge = document.getElementById("alerts-table-badge");
    if (countBadge) countBadge.textContent = `${allAlerts.length} security alerts recorded`;
}

function filterAlerts(severity) {
    activeFilter = severity;
    const tbody = document.getElementById("alerts-body");
    if (!tbody) return;
    tbody.innerHTML = "";

    const filtered = allAlerts.filter(a => severity === "ALL" || a.severity === severity);
    if (filtered.length === 0) {
        tbody.innerHTML = '<tr class="empty-row"><td colspan="7">No security events match the current filter.</td></tr>';
        return;
    }
    filtered.forEach(a => renderAlertRow(a, false));
}

let currentExplainingAlert = null;

function openExplainModal(alertId) {
    const alert = allAlerts.find(a => a.id === alertId) || allAlerts[0];
    if (!alert) return;
    currentExplainingAlert = alert;

    const expl = ATTACK_EXPLANATIONS[alert.type] || {
        what: `A ${alert.type} security event was detected originating from ${alert.src_ip}.`,
        trigger: "Heuristic rules evaluated anomalous volume and breached security parameters.",
        impact: "Hostile traffic could compromise application availability and reveal network topology.",
        defense: "Block the source IP address immediately and inspect upstream traffic access lists."
    };

    document.getElementById("explain-heading").textContent = `🔍 Incident Analysis: ${alert.type}`;
    document.getElementById("explain-what").textContent = expl.what;
    document.getElementById("explain-trigger").textContent = expl.trigger;
    document.getElementById("explain-impact").textContent = expl.impact;
    document.getElementById("explain-defense").textContent = expl.defense;

    const ip = alert.src_ip || "0.0.0.0";
    document.getElementById("fw-linux").textContent = `sudo iptables -A INPUT -s ${ip} -j DROP`;
    document.getElementById("fw-windows").textContent = `netsh advfirewall firewall add rule name="NetGuard_Block_${ip}" dir=in action=block remoteip=${ip}`;

    const enforceBtn = document.getElementById("btn-enforce-block");
    if (enforceBtn) {
        enforceBtn.textContent = "🚫 Enforce Kernel Block";
        enforceBtn.disabled = false;
        enforceBtn.style.background = "#7f1d1d";
        enforceBtn.style.borderColor = "#b91c1c";
    }

    const pcapLink = document.getElementById("btn-incident-pcap");
    if (pcapLink) {
        pcapLink.href = `/api/export/pcap/alert/${alert.id}`;
        pcapLink.download = `incident_${(alert.id||'').slice(0,8)}.pcap`;
    }

    const defStatus = document.getElementById("explain-defense-status");
    if (defStatus) defStatus.textContent = "SOAR active defense rule ready to deploy.";

    document.getElementById("explain-modal").classList.remove("hidden");
}

function closeExplainModal() {
    document.getElementById("explain-modal").classList.add("hidden");
}

function copyRule(elId) {
    const el = document.getElementById(elId);
    if (!el) return;
    navigator.clipboard.writeText(el.textContent).then(() => {
        showToast("Firewall block rule copied to clipboard!", "success");
    });
}

function openEvidenceModal(alertId) {
    const alert = allAlerts.find(a => a.id === alertId);
    if (!alert) return;

    document.getElementById("modal-type").textContent = alert.type;
    document.getElementById("modal-severity").textContent = alert.severity;
    document.getElementById("modal-src").textContent = alert.src_ip;
    document.getElementById("modal-dst").textContent = alert.dst_ip;
    document.getElementById("modal-summary").textContent = alert.summary;
    document.getElementById("modal-json").textContent = JSON.stringify(alert.evidence, null, 2);
    document.getElementById("evidence-modal").classList.remove("hidden");
}

function closeModal() {
    document.getElementById("evidence-modal").classList.add("hidden");
}

async function clearAlerts() {
    try {
        await fetch("/api/alerts", { method: "DELETE" });
        allAlerts = [];
        filterAlerts("ALL");
        updateAlertStats();
        showToast("Security alert log purged.", "info");
    } catch (err) {
        console.error("Clear alerts error:", err);
    }
}

// =============================================================================
// 8. Attack Simulation Triggers
// =============================================================================
async function triggerAttack(attackType) {
    const badge = document.getElementById("attack-status");
    if (badge) {
        badge.innerHTML = '<span class="status-dot" style="background:#ef4444;"></span> Injecting Vector...';
    }

    try {
        const res = await fetch("/api/simulate", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ type: attackType }),
        });
        const data = await res.json();
        if (res.ok) {
            showToast(`Injected attack vector: ${attackType.toUpperCase()}`, "danger");
        } else {
            showToast(`Attack injection failed: ${data.error}`, "danger");
        }
    } catch (err) {
        showToast(`Simulation error: ${err.message}`, "danger");
    } finally {
        setTimeout(() => {
            if (badge) badge.innerHTML = '<span class="status-dot"></span> Simulator Ready';
        }, 1500);
    }
}

// =============================================================================
// 9. Forensics: Connected Devices & Packet Inspector
// =============================================================================
async function refreshDevices() {
    try {
        const res = await fetch("/api/devices?limit=50");
        if (!res.ok) return;
        const data = await res.json();
        const devices = data.devices || [];
        const tbody = document.getElementById("devices-body");
        if (!tbody) return;
        tbody.innerHTML = "";

        const totalEl = document.getElementById("device-total");
        const localEl = document.getElementById("device-local");
        const extEl = document.getElementById("device-external");
        const flagEl = document.getElementById("device-flagged");
        if (totalEl) totalEl.textContent = devices.length;
        if (localEl) localEl.textContent = devices.filter(d => d.role === "local" || d.role === "gateway").length;
        if (extEl) extEl.textContent = devices.filter(d => d.role === "external").length;
        if (flagEl) flagEl.textContent = devices.filter(d => d.is_flagged).length;

        if (devices.length === 0) {
            tbody.innerHTML = '<tr class="empty-row"><td colspan="9">No devices observed yet. Traffic will populate this view.</td></tr>';
            return;
        }

        devices.forEach(d => {
            const tr = document.createElement("tr");
            const roleCls = d.is_flagged ? "attacker" : d.role;
            const roleLabel = d.is_flagged ? "ATTACKER" : (d.role || "unknown").toUpperCase();
            const protocols = (d.protocols_used || []).join(", ");
            const kb = (d.total_bytes / 1024).toFixed(1);
            const ports = (d.ports_seen || []).slice(0, 5).join(", ");
            const firstSeen = formatTimestamp(d.first_seen, true);
            const lastSeen = formatTimestamp(d.last_seen, true);
            const statusDot = d.is_flagged ? "flagged" : "active";
            const statusText = d.is_flagged ? `⚠ ${d.alert_count} alerts` : "Clean";

            tr.innerHTML = `
                <td><code class="ip-pill ${d.is_flagged ? 'source' : ''}">${d.ip}</code></td>
                <td><span class="role-badge ${roleCls}">${roleLabel}</span></td>
                <td>${protocols || "IP"}</td>
                <td>${d.total_packets.toLocaleString()}</td>
                <td>${kb} KB</td>
                <td style="font-family:var(--font-mono);font-size:11px;">${ports || "--"}</td>
                <td>${firstSeen}</td>
                <td>${lastSeen}</td>
                <td><span class="status-indicator"><span class="dot ${statusDot}"></span>${statusText}</span></td>
            `;
            tbody.appendChild(tr);
        });
    } catch (err) {
        console.error("Devices fetch error:", err);
    }
}

async function refreshConnections() {
    try {
        const res = await fetch("/api/connections");
        if (!res.ok) return;
        const data = await res.json();
        const flows = data.flows || [];
        const tbody = document.getElementById("connections-body");
        if (!tbody) return;
        tbody.innerHTML = "";

        let halfOpen = 0;
        flows.forEach(f => { if (f.state === "HALF_OPEN") halfOpen++; });
        const hoEl = document.getElementById("kpi-half-open");
        if (hoEl) hoEl.textContent = `${halfOpen} half-open`;

        if (flows.length === 0) {
            tbody.innerHTML = '<tr class="empty-row"><td colspan="8">No active TCP connections currently tracked.</td></tr>';
            return;
        }

        flows.forEach(f => {
            const tr = document.createElement("tr");
            tr.innerHTML = `
                <td><code class="ip-pill">${f.flow_id}</code></td>
                <td>${f.src_ip}:${f.src_port}</td>
                <td>${f.dst_ip}:${f.dst_port}</td>
                <td><span class="tag-state ${f.state.toLowerCase()}">${f.state}</span></td>
                <td>${f.duration_s}s</td>
                <td>${f.packet_count}</td>
                <td>${(f.byte_count / 1024).toFixed(1)} KB</td>
                <td>${formatTimestamp(f.last_seen, true)}</td>
            `;
            tbody.appendChild(tr);
        });
    } catch (err) {
        console.error("Connections fetch error:", err);
    }
}

function handleNewPacket(pkt) {
    packetCounter++;
    pkt._num = packetCounter;
    packetBuffer.unshift(pkt);
    if (packetBuffer.length > 150) packetBuffer.pop();
    if (!isStreamPaused) renderPacketRow(pkt, true);
    addPipelineParticle(false);
}

function renderPacketRow(pkt, isPrepend) {
    if (packetProtoFilter !== "ALL" && pkt.proto !== packetProtoFilter) return;
    const query = (document.getElementById("packet-search")?.value || "").toLowerCase();
    if (query) {
        const str = `${pkt.src_ip} ${pkt.dst_ip} ${pkt.src_port} ${pkt.dst_port} ${pkt.proto} ${pkt.info}`.toLowerCase();
        if (!str.includes(query)) return;
    }

    const tbody = document.getElementById("packet-stream-body");
    if (!tbody) return;
    const empty = tbody.querySelector(".empty-row");
    if (empty) empty.remove();

    const tr = document.createElement("tr");
    const timeStr = formatTimestamp(pkt.ts, true);

    tr.innerHTML = `
        <td style="font-family:var(--font-mono);font-size:11px;">#${pkt._num}</td>
        <td style="font-family:var(--font-mono);font-size:11px;">${timeStr}</td>
        <td><code class="ip-pill">${pkt.src_port ? `${pkt.src_ip}:${pkt.src_port}` : pkt.src_ip}</code></td>
        <td><code class="ip-pill">${pkt.dst_port ? `${pkt.dst_ip}:${pkt.dst_port}` : pkt.dst_ip}</code></td>
        <td><span class="tag ${pkt.proto === 'TCP' ? 'tag-low' : pkt.proto === 'ICMP' ? 'tag-medium' : 'tag-high'}">${pkt.proto}</span></td>
        <td>${pkt.length} B</td>
        <td>${pkt.ttl !== null ? pkt.ttl : '--'}</td>
        <td style="font-size:11px;color:var(--text-secondary);">${pkt.info || '--'}</td>
        <td><button class="btn-inspect" onclick="openPacketModal(${pkt._num})">View</button></td>
    `;

    tr._packetData = pkt;

    if (isPrepend && tbody.firstChild) tbody.insertBefore(tr, tbody.firstChild);
    else tbody.appendChild(tr);

    while (tbody.children.length > 80) tbody.removeChild(tbody.lastChild);
}

function togglePacketStream() {
    isStreamPaused = !isStreamPaused;
    const btn = document.getElementById("btn-stream-toggle");
    if (btn) {
        btn.innerHTML = isStreamPaused
            ? '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="5 3 19 12 5 21 5 3"/></svg> Resume Stream'
            : '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="6" y="4" width="4" height="16"/><rect x="14" y="4" width="4" height="16"/></svg> Pause Stream';
    }
}

function clearPacketBuffer() {
    packetBuffer = [];
    const tbody = document.getElementById("packet-stream-body");
    if (tbody) tbody.innerHTML = '<tr class="empty-row"><td colspan="9">Buffer cleared. Stream active.</td></tr>';
}

function setPacketProtoFilter(proto) {
    packetProtoFilter = proto;
    document.querySelectorAll(".pill-group .pill").forEach(p => {
        p.classList.toggle("active", p.textContent.trim().toUpperCase() === proto);
    });
    filterPacketTable();
}

function filterPacketTable() {
    const tbody = document.getElementById("packet-stream-body");
    if (!tbody) return;
    tbody.innerHTML = "";
    const filtered = packetBuffer.filter(pkt => {
        if (packetProtoFilter !== "ALL" && pkt.proto !== packetProtoFilter) return false;
        const query = (document.getElementById("packet-search")?.value || "").toLowerCase();
        if (!query) return true;
        return `${pkt.src_ip} ${pkt.dst_ip} ${pkt.src_port} ${pkt.dst_port} ${pkt.proto} ${pkt.info}`.toLowerCase().includes(query);
    });

    if (filtered.length === 0) {
        tbody.innerHTML = '<tr class="empty-row"><td colspan="9">No packets match search query.</td></tr>';
        return;
    }
    filtered.forEach(p => renderPacketRow(p, false));
}

function openPacketModal(num) {
    const pkt = packetBuffer.find(p => p._num === num);
    if (!pkt) return;

    document.getElementById("dissect-iface").textContent = pkt.iface || "eth0";
    document.getElementById("dissect-len").textContent = pkt.length;
    document.getElementById("dissect-ipver").textContent = pkt.ip_ver || 4;
    document.getElementById("dissect-srcip").textContent = pkt.src_ip;
    document.getElementById("dissect-dstip").textContent = pkt.dst_ip;
    document.getElementById("dissect-ttl").textContent = pkt.ttl !== null ? pkt.ttl : "64";
    document.getElementById("dissect-proto").textContent = pkt.proto;

    const l4 = document.getElementById("dissect-l4-node");
    if (pkt.proto === "TCP" || pkt.proto === "UDP") {
        l4.style.display = "block";
        document.getElementById("dissect-l4-proto").textContent = pkt.proto;
        document.getElementById("dissect-sport").textContent = pkt.src_port || "--";
        document.getElementById("dissect-dport").textContent = pkt.dst_port || "--";
        document.getElementById("dissect-flags").textContent = pkt.tcp_flags || "None";
        document.getElementById("dissect-seq").textContent = pkt.seq !== null ? pkt.seq : "--";
        document.getElementById("dissect-ack").textContent = pkt.ack !== null ? pkt.ack : "--";
        document.getElementById("dissect-win").textContent = pkt.window !== null ? pkt.window : "65535";
    } else {
        l4.style.display = "none";
    }

    document.getElementById("packet-dissector-modal").classList.remove("hidden");
}

function closePacketModal() {
    document.getElementById("packet-dissector-modal").classList.add("hidden");
}

// =============================================================================
// 10. Threat Map
// =============================================================================
function initThreatMap() {
    if (threatMap) return;
    const mapEl = document.getElementById("threat-map");
    if (!mapEl) return;

    threatMap = L.map("threat-map", {
        center: [20, 0],
        zoom: 2,
        minZoom: 1.5,
        maxZoom: 8,
        attributionControl: false,
    });

    L.tileLayer("https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png", {
        maxZoom: 19,
    }).addTo(threatMap);
}

async function refreshThreatMap() {
    initThreatMap();
    if (!threatMap) return;

    try {
        const res = await fetch("/api/geo/attackers");
        if (!res.ok) return;
        const data = await res.json();
        const locations = data.locations || [];

        threatMarkers.forEach(m => threatMap.removeLayer(m));
        threatMarkers = [];

        const tbody = document.getElementById("geo-table-body");
        if (tbody) tbody.innerHTML = "";

        if (locations.length === 0) {
            if (tbody) tbody.innerHTML = '<tr class="empty-row"><td colspan="6">No external attacker locations mapped yet.</td></tr>';
            return;
        }

        locations.forEach(loc => {
            const marker = L.circleMarker([loc.lat, loc.lon], {
                radius: 6,
                fillColor: "#ef4444",
                color: "#fca5a5",
                weight: 1,
                opacity: 0.9,
                fillOpacity: 0.8,
            }).addTo(threatMap);

            marker.bindPopup(`
                <div style="font-family:sans-serif;font-size:12px;color:#1e293b;">
                    <strong>${loc.ip}</strong><br>
                    Location: ${loc.city}, ${loc.country}<br>
                    Org: ${loc.org}<br>
                    Attack Type: ${loc.last_type} (${loc.alert_count} alerts)
                </div>
            `);
            threatMarkers.push(marker);

            if (tbody) {
                const tr = document.createElement("tr");
                tr.innerHTML = `
                    <td><code class="ip-pill source">${loc.ip}</code></td>
                    <td>${loc.city}, ${loc.country}</td>
                    <td>${loc.org}</td>
                    <td>${loc.alert_count}</td>
                    <td><strong>${loc.last_type}</strong></td>
                    <td><button class="btn-inspect" onclick="openExplainModal('${loc.ip}')">Explain</button></td>
                `;
                tbody.appendChild(tr);
            }
        });
    } catch (err) {
        console.error("Threat map error:", err);
    }
}

// =============================================================================
// 11. Initial Data Fetch & Settings
// =============================================================================
async function fetchInitialData() {
    try {
        const [alertsRes, historyRes] = await Promise.all([
            fetch("/api/alerts?limit=50"),
            fetch("/api/metrics/history")
        ]);

        if (alertsRes.ok) {
            const data = await alertsRes.json();
            allAlerts = data.alerts || [];
            filterAlerts("ALL");
            updateAlertStats();
        }

        if (historyRes.ok) {
            const data = await historyRes.json();
            const history = data.history || [];
            if (bandwidthChart && history.length > 0) {
                history.forEach(m => {
                    const timeLabel = formatTimestamp(m.ts, true);
                    const kbPerSec = (m.bps / 1024).toFixed(1);
                    bandwidthChart.data.labels.push(timeLabel);
                    bandwidthChart.data.datasets[0].data.push(parseFloat(kbPerSec));
                    bandwidthChart.data.datasets[1].data.push(m.pps);
                });
                bandwidthChart.update();
            }
        }
    } catch (err) {
        console.error("Initial data load error:", err);
    }
}

async function loadCurrentConfig() {
    try {
        const res = await fetch("/api/config");
        if (!res.ok) return;
        const data = await res.json();
        const rules = data.rules || {};
        if (rules.port_scan) {
            document.getElementById("cfg-port-threshold").value = rules.port_scan.threshold;
            document.getElementById("cfg-port-window").value = rules.port_scan.window_s;
        }
        if (rules.syn_flood) {
            document.getElementById("cfg-syn-threshold").value = rules.syn_flood.threshold;
            document.getElementById("cfg-syn-ratio").value = rules.syn_flood.ratio;
        }
        if (rules.udp_flood) {
            document.getElementById("cfg-udp-threshold").value = rules.udp_flood.threshold;
        }
    } catch (err) {
        console.error("Config fetch error:", err);
    }
}

async function applyConfigUpdates() {
    const payload = {
        port_scan_threshold: parseInt(document.getElementById("cfg-port-threshold").value),
        port_scan_window: parseFloat(document.getElementById("cfg-port-window").value),
        syn_threshold: parseInt(document.getElementById("cfg-syn-threshold").value),
        syn_ratio: parseFloat(document.getElementById("cfg-syn-ratio").value),
        udp_threshold: parseInt(document.getElementById("cfg-udp-threshold").value),
    };

    try {
        const res = await fetch("/api/config", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload),
        });
        showToast(res.ok ? "Heuristic thresholds updated live." : "Failed to update config.", res.ok ? "success" : "danger");
    } catch (err) {
        showToast(`Config error: ${err.message}`, "danger");
    }
}

async function loadEmailSettings() {
    try {
        const res = await fetch("/api/settings/email");
        if (!res.ok) return;
    } catch (err) {}
}

function showToast(message, type = "info") {
    const container = document.getElementById("toast-container");
    if (!container) return;

    const toast = document.createElement("div");
    toast.className = `toast toast-${type}`;
    toast.textContent = message;
    container.appendChild(toast);

    setTimeout(() => {
        if (toast.parentNode) toast.parentNode.removeChild(toast);
    }, 3800);
}

// =============================================================================
// 12. Active Defense SOAR & Rate Control
// =============================================================================
async function enforceActiveDefense() {
    if (!currentExplainingAlert || !currentExplainingAlert.src_ip) return;
    const ip = currentExplainingAlert.src_ip;
    const btn = document.getElementById("btn-enforce-block");
    try {
        const res = await fetch("/api/blacklist", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ ip: ip, reason: `Active SOAR Enforcement for ${currentExplainingAlert.type}` }),
        });
        if (res.ok) {
            if (btn) {
                btn.textContent = "✅ Enforced (Kernel Dropped)";
                btn.style.background = "#064e3b";
                btn.style.borderColor = "#059669";
                btn.disabled = true;
            }
            const statusEl = document.getElementById("explain-defense-status");
            if (statusEl) statusEl.textContent = `IP ${ip} permanently added to kernel drop table.`;
            showToast(`Active Defense Enforced: ${ip} dropped.`, "success");
        }
    } catch (e) {
        showToast(`SOAR error: ${e.message}`, "danger");
    }
}

async function setSimRate(rate, btnEl) {
    document.querySelectorAll(".speed-btn").forEach(b => b.classList.remove("active"));
    if (btnEl) btnEl.classList.add("active");
    try {
        const res = await fetch("/api/simulate/rate", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ rate: rate }),
        });
        if (res.ok) {
            showToast(`Traffic generator speed set to ${rate}x multiplier`, "info");
        }
    } catch (err) {
        console.error("Set rate error:", err);
    }
}

// =============================================================================
// 13. Guided Tour / Demo Walkthrough
// =============================================================================
const TOUR_STEPS = [
    {
        title: "1. Real-Time Packet Pipeline",
        desc: "Watch live packets traverse from NIC Ingress into the Ring Buffer, get parsed at Layer-3/4, evaluated by 6 active heuristic engines, and trigger automated SOAR responses.",
        tab: "network",
    },
    {
        title: "2. Dual-Axis Telemetry & Statistical Corridor",
        desc: "The left Y-axis plots Throughput (KB/s) while the right Y-axis plots PPS. The red dashed ceiling represents the dynamic baseline (μ + 2σ). A spike breaching this corridor indicates an anomaly.",
        tab: "network",
    },
    {
        title: "3. Heuristic Diagnostic Interpreter",
        desc: "This banner automatically translates mathematical ratios and average packet sizes into plain-English security diagnoses (e.g. Small Packets + High PPS = SYN Flood).",
        tab: "network",
    },
    {
        title: "4. Attack Simulation Lab & DNS Tunneling",
        desc: "Test detection with one click. NetGuard simulates RFC-compliant reconnaissance, volumetric floods, and covert DNS tunneling exfiltration directly into the live pipeline.",
        tab: "threats",
    },
    {
        title: "5. Incident Analysis & Active Defense (SOAR)",
        desc: "Click 'Explain' on any alert to see what happened, trigger criteria, real-world impact, and immediately enforce kernel-level firewall drops (iptables & netsh).",
        tab: "threats",
    },
    {
        title: "6. Deep Forensics & Incident PCAP",
        desc: "Inspect connected devices, track RFC 793 stateful TCP handshakes, and download incident-specific Wireshark .pcap files containing the exact packets that caused an alert.",
        tab: "forensics",
    }
];

let currentTourStep = 0;

function startGuidedTour() {
    currentTourStep = 0;
    const overlay = document.getElementById("tour-overlay");
    if (overlay) {
        overlay.classList.remove("hidden");
        overlay.style.display = "flex";
    }
    renderTourStep();
}

function stopGuidedTour() {
    const overlay = document.getElementById("tour-overlay");
    if (overlay) {
        overlay.classList.add("hidden");
        overlay.style.display = "none";
    }
    localStorage.setItem("netguard_tour_dismissed", "true");
    switchTab("network");
}

function nextTourStep() {
    if (currentTourStep < TOUR_STEPS.length - 1) {
        currentTourStep++;
        renderTourStep();
    } else {
        stopGuidedTour();
        showToast("Tour completed! Welcome to NetGuard SOC.", "success");
    }
}

function prevTourStep() {
    if (currentTourStep > 0) {
        currentTourStep--;
        renderTourStep();
    }
}

function renderTourStep() {
    const step = TOUR_STEPS[currentTourStep];
    switchTab(step.tab);
    const ind = document.getElementById("tour-step-indicator");
    const title = document.getElementById("tour-step-title");
    const desc = document.getElementById("tour-step-desc");
    const prevBtn = document.getElementById("tour-prev-btn");
    const nextBtn = document.getElementById("tour-next-btn");

    if (ind) ind.textContent = `Step ${currentTourStep + 1} of ${TOUR_STEPS.length}`;
    if (title) title.textContent = step.title;
    if (desc) desc.textContent = step.desc;
    if (prevBtn) prevBtn.style.visibility = currentTourStep === 0 ? "hidden" : "visible";
    if (nextBtn) nextBtn.textContent = currentTourStep === TOUR_STEPS.length - 1 ? "Finish Tour" : "Next Step →";
}

// Global Keyboard Shortcuts (Escape to dismiss modals & tour)
document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") {
        const tourOverlay = document.getElementById("tour-overlay");
        if (tourOverlay && tourOverlay.style.display !== "none" && !tourOverlay.classList.contains("hidden")) {
            stopGuidedTour();
            return;
        }
        closeModal();
        closePacketModal();
        closeExplainModal();
    }
});

// Explicitly register window exports for HTML inline handlers
window.startGuidedTour = startGuidedTour;
window.stopGuidedTour = stopGuidedTour;
window.nextTourStep = nextTourStep;
window.prevTourStep = prevTourStep;

