/* ── Dashboard main.js — with auto-polling every 5 seconds ─────────────── */

let typeChart    = null;
let timelineChart = null;
let pollInterval  = null;

// ── Boot ──────────────────────────────────────────────────────────────────────
document.addEventListener("DOMContentLoaded", () => {
    loadAll();
    // Poll every 5 seconds — no Socket.IO dependency
    pollInterval = setInterval(loadAll, 5000);
});

// ── Master loader ─────────────────────────────────────────────────────────────
async function loadAll() {
    try {
        const [statsRes, sessRes, typeRes, timelineRes, ipRes, iocRes] = await Promise.all([
            fetch("/api/stats"),
            fetch("/api/sessions?limit=30"),
            fetch("/api/attacker_types"),
            fetch("/api/threat_timeline"),
            fetch("/api/top_ips"),
            fetch("/api/iocs"),
        ]);

        const stats    = await statsRes.json();
        const sessions = await sessRes.json();
        const types    = await typeRes.json();
        const timeline = await timelineRes.json();
        const topIPs   = await ipRes.json();
        const iocs     = await iocRes.json();

        renderStats(stats, iocs.length);
        renderSessionTable(sessions);
        renderTopIPs(topIPs);
        renderCharts(types, timeline);
        setLive(true);
    } catch (e) {
        setLive(false);
        console.error("Dashboard poll error:", e);
    }
}

// ── Stats cards ───────────────────────────────────────────────────────────────
function renderStats(data, iocCount) {
    setText("stat-sessions", data.total_sessions  ?? 0);
    setText("stat-high",     data.high_threat      ?? 0);
    setText("stat-malware",  data.malware_caught   ?? 0);
    setText("stat-iocs",     iocCount              ?? 0);
}

function setText(id, val) {
    const el = document.getElementById(id);
    if (el) el.textContent = val;
}

// ── Session table ─────────────────────────────────────────────────────────────
function renderSessionTable(sessions) {
    const tbody = document.getElementById("session-body");
    if (!tbody) return;

    if (!sessions || sessions.length === 0) {
        tbody.innerHTML = `<tr><td colspan="6" style="text-align:center;color:#94a3b8;padding:20px">
            No sessions yet — waiting for attackers...
        </td></tr>`;
        return;
    }

    tbody.innerHTML = sessions.map(s => `
        <tr>
            <td><code>${s.ip || "—"}</code></td>
            <td>${s.start_time ? new Date(s.start_time * 1000).toLocaleTimeString() : "—"}</td>
            <td>${s.command_count ?? 0}</td>
            <td><span class="badge badge-${typeBadge(s.attacker_type)}">${s.attacker_type || "unknown"}</span></td>
            <td><strong>${s.threat_score ?? 0}</strong></td>
            <td><span class="badge badge-${levelBadge(s.threat_level)}">${s.threat_level || "LOW"}</span></td>
        </tr>`).join("");
}

// ── Top IPs table ─────────────────────────────────────────────────────────────
function renderTopIPs(topIPs) {
    const tbody = document.getElementById("top-ip-body");
    if (!tbody) return;

    if (!topIPs || topIPs.length === 0) {
        tbody.innerHTML = `<tr><td colspan="3" style="text-align:center;color:#94a3b8;padding:12px">No data yet</td></tr>`;
        return;
    }

    tbody.innerHTML = topIPs.map(r => `
        <tr>
            <td><code>${r.ip}</code></td>
            <td>${r.hits}</td>
            <td><strong>${r.max_score}</strong></td>
        </tr>`).join("");
}

// ── Charts ────────────────────────────────────────────────────────────────────
function renderCharts(types, timeline) {
    renderTypeChart(types);
    renderTimelineChart(timeline);
}

function renderTypeChart(types) {
    const ctx = document.getElementById("typeChart");
    if (!ctx) return;

    const labels = types.map(t => t.attacker_type || "unknown");
    const data   = types.map(t => t.count);

    if (typeChart) {
        typeChart.data.labels   = labels;
        typeChart.data.datasets[0].data = data;
        typeChart.update();
        return;
    }

    if (!labels.length) return;

    typeChart = new Chart(ctx, {
        type: "doughnut",
        data: {
            labels,
            datasets: [{
                data,
                backgroundColor: ["#3b82f6","#10b981","#ef4444","#6b7280","#f59e0b"],
            }],
        },
        options: {
            plugins: { legend: { labels: { color: "#e2e8f0" } } },
            responsive: true,
        },
    });
}

function renderTimelineChart(timeline) {
    const ctx = document.getElementById("timelineChart");
    if (!ctx || !timeline.length) return;

    const sorted = [...timeline].reverse();
    const labels = sorted.map(e => new Date(e.ts * 1000).toLocaleTimeString());
    const data   = sorted.map(e => e.threat_score);

    if (timelineChart) {
        timelineChart.data.labels            = labels;
        timelineChart.data.datasets[0].data  = data;
        timelineChart.update();
        return;
    }

    timelineChart = new Chart(ctx, {
        type: "line",
        data: {
            labels,
            datasets: [{
                label:           "Threat Score",
                data,
                borderColor:     "#3b82f6",
                backgroundColor: "rgba(59,130,246,0.1)",
                pointRadius:     3,
                tension:         0.3,
                fill:            true,
            }],
        },
        options: {
            scales: {
                x: { ticks: { color: "#94a3b8", maxTicksLimit: 8 }, grid: { color: "#2a2d3a" } },
                y: { min: 0, max: 100, ticks: { color: "#94a3b8" }, grid: { color: "#2a2d3a" } },
            },
            plugins: { legend: { labels: { color: "#e2e8f0" } } },
            responsive: true,
        },
    });
}

// ── Live indicator ────────────────────────────────────────────────────────────
function setLive(on) {
    const badge = document.getElementById("live-badge");
    if (!badge) return;
    badge.textContent = on ? "● LIVE" : "● OFFLINE";
    badge.className   = "badge " + (on ? "badge-green" : "badge-danger");
}

// ── Helpers ───────────────────────────────────────────────────────────────────
function levelBadge(l) {
    return { LOW:"green", MEDIUM:"warn", HIGH:"orange", CRITICAL:"danger" }[l] || "info";
}
function typeBadge(t) {
    return { bot:"info", human:"green", advanced:"danger", unknown:"warn" }[t] || "warn";
}
