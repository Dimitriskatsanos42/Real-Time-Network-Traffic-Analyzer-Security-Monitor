/**
 * Network Security Monitor — Dashboard JavaScript
 *
 * Λειτουργίες:
 *   - JWT authentication & token management
 *   - Real-time data refresh (polling)
 *   - Dark/Light theme toggle
 *   - CSV & PDF export
 *   - Chart.js visualizations
 */

const REFRESH_INTERVAL = 3000;
const TOKEN_KEY = "nsm_jwt_token";
const THEME_KEY = "nsm_theme";

let protocolChart = null;
let topIpsChart = null;
let refreshTimer = null;

// ── Authentication ──────────────────────────────────────────────────

function getToken() {
    return localStorage.getItem(TOKEN_KEY);
}

function setToken(token) {
    localStorage.setItem(TOKEN_KEY, token);
}

function clearToken() {
    localStorage.removeItem(TOKEN_KEY);
}

function isAuthenticated() {
    return !!getToken();
}

async function fetchJSON(url, options = {}) {
    const headers = { ...(options.headers || {}) };
    const token = getToken();
    if (token) {
        headers["Authorization"] = `Bearer ${token}`;
    }

    const res = await fetch(url, { ...options, headers });

    if (res.status === 401) {
        clearToken();
        showLogin();
        throw new Error("Unauthorized");
    }

    return res.json();
}

function showLogin() {
    document.getElementById("login-modal").classList.remove("hidden");
    disableControls(true);
}

function hideLogin() {
    document.getElementById("login-modal").classList.add("hidden");
    disableControls(false);
}

function disableControls(disabled) {
    ["btn-start", "btn-stop", "btn-export"].forEach((id) => {
        const el = document.getElementById(id);
        if (el) el.disabled = disabled;
    });
}

function bindAuthEvents() {
    const loginForm = document.getElementById("login-form");
    const logoutButton = document.getElementById("btn-logout");

    if (loginForm) {
        loginForm.addEventListener("submit", async (e) => {
            e.preventDefault();
            const username = document.getElementById("login-username").value;
            const password = document.getElementById("login-password").value;
            const errorEl = document.getElementById("login-error");

            try {
                const res = await fetch("/api/auth/login", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ username, password }),
                });
                const data = await res.json();

                if (!res.ok) {
                    errorEl.textContent = data.error || "Login failed";
                    return;
                }

                setToken(data.token);
                errorEl.textContent = "";
                hideLogin();
                if (logoutButton) {
                    logoutButton.style.display = "inline-block";
                }
                startRefresh();
            } catch {
                if (errorEl) {
                    errorEl.textContent = "Connection error";
                }
            }
        });
    }

    if (logoutButton) {
        logoutButton.addEventListener("click", () => {
            clearToken();
            stopRefresh();
            showLogin();
            logoutButton.style.display = "none";
        });
    }
}

// ── Theme Toggle ──────────────────────────────────────────────────

function initTheme() {
    const saved = localStorage.getItem(THEME_KEY) || "dark";
    document.documentElement.setAttribute("data-theme", saved);
    updateThemeIcon(saved);
}

function toggleTheme() {
    const current = document.documentElement.getAttribute("data-theme");
    const next = current === "dark" ? "light" : "dark";
    document.documentElement.setAttribute("data-theme", next);
    localStorage.setItem(THEME_KEY, next);
    updateThemeIcon(next);
    // Re-render charts with new colors
    protocolChart = null;
    topIpsChart = null;
    refreshAll();
}

function updateThemeIcon(theme) {
    document.getElementById("btn-theme").textContent = theme === "dark" ? "\u263E" : "\u2600";
}

document.getElementById("btn-theme").addEventListener("click", toggleTheme);

// ── Formatting Helpers ────────────────────────────────────────────

function formatTime(iso) {
    if (!iso) return "-";
    return new Date(iso).toLocaleTimeString("el-GR", {
        hour: "2-digit", minute: "2-digit", second: "2-digit",
    });
}

function formatBytes(bytes) {
    if (bytes < 1024) return bytes + " B";
    if (bytes < 1048576) return (bytes / 1024).toFixed(1) + " KB";
    return (bytes / 1048576).toFixed(1) + " MB";
}

function chartColors() {
    const theme = document.documentElement.getAttribute("data-theme");
    return {
        text: theme === "dark" ? "#9ca3af" : "#64748b",
        grid: theme === "dark" ? "#374151" : "#e2e8f0",
    };
}

// ── Data Refresh Functions ──────────────────────────────────────────

function updateCaptureStatus(running) {
    const badge = document.getElementById("capture-status");
    const btnStart = document.getElementById("btn-start");
    const btnStop = document.getElementById("btn-stop");

    badge.textContent = running ? "Running" : "Stopped";
    badge.className = `status-badge ${running ? "status-running" : "status-stopped"}`;
    btnStart.disabled = running || !isAuthenticated();
    btnStop.disabled = !running || !isAuthenticated();
}

async function refreshStats() {
    const data = await fetchJSON("/api/stats");
    document.getElementById("stat-packets").textContent = data.total_packets.toLocaleString();
    document.getElementById("stat-packets-hour").textContent = data.packets_last_hour.toLocaleString();
    document.getElementById("stat-alerts").textContent = data.unacknowledged_alerts.toLocaleString();
    document.getElementById("stat-dns").textContent = data.total_dns_queries.toLocaleString();
    document.getElementById("stat-suspicious-dns").textContent = data.suspicious_dns_queries.toLocaleString();
    document.getElementById("stat-failed-logins").textContent = (data.failed_logins || 0).toLocaleString();
    document.getElementById("stat-brute-force").textContent = (data.brute_force_alerts || 0).toLocaleString();
    document.getElementById("stat-blacklist").textContent = (data.blacklist_hits || 0).toLocaleString();
    updateProtocolChart(data.protocols);
}

function updateProtocolChart(protocols) {
    const ctx = document.getElementById("protocol-chart");
    const colors = chartColors();
    const labels = Object.keys(protocols);
    const values = Object.values(protocols);

    if (protocolChart) {
        protocolChart.data.labels = labels;
        protocolChart.data.datasets[0].data = values;
        protocolChart.update();
        return;
    }

    protocolChart = new Chart(ctx, {
        type: "doughnut",
        data: {
            labels,
            datasets: [{
                data: values,
                backgroundColor: ["#3b82f6", "#22c55e", "#f59e0b", "#8b5cf6", "#64748b"],
            }],
        },
        options: {
            responsive: true,
            plugins: { legend: { position: "bottom", labels: { color: colors.text } } },
        },
    });
}

async function refreshTopIPs() {
    const data = await fetchJSON("/api/top-ips?limit=10");
    const colors = chartColors();
    const ctx = document.getElementById("top-ips-chart");
    const labels = data.map((r) => `${r.ip_address} (${r.country_code || "?"})`);
    const values = data.map((r) => r.packet_count);

    if (topIpsChart) {
        topIpsChart.data.labels = labels;
        topIpsChart.data.datasets[0].data = values;
        topIpsChart.update();
        return;
    }

    topIpsChart = new Chart(ctx, {
        type: "bar",
        data: {
            labels,
            datasets: [{ label: "Packets", data: values, backgroundColor: "#3b82f6" }],
        },
        options: {
            responsive: true,
            indexAxis: "y",
            plugins: { legend: { display: false } },
            scales: {
                x: { ticks: { color: colors.text }, grid: { color: colors.grid } },
                y: { ticks: { color: colors.text, font: { size: 10 } }, grid: { color: colors.grid } },
            },
        },
    });

    // Top IPs table
    const tbody = document.getElementById("topips-body");
    if (!data.length) {
        tbody.innerHTML = '<tr><td colspan="5" class="empty">No data</td></tr>';
        return;
    }
    tbody.innerHTML = data.map((ip) => `
        <tr>
            <td>${ip.ip_address}</td>
            <td>${ip.country || "Unknown"}</td>
            <td>${ip.packet_count.toLocaleString()}</td>
            <td>${formatBytes(ip.byte_count)}</td>
            <td class="${ip.is_blacklisted ? "tag-blacklisted" : "tag-normal"}">
                ${ip.is_blacklisted ? "BLACKLISTED" : "No"}
            </td>
        </tr>
    `).join("");
}

async function refreshAlerts() {
    const data = await fetchJSON("/api/alerts?limit=20&unacknowledged=true");
    const tbody = document.getElementById("alerts-body");
    if (!data.length) {
        tbody.innerHTML = '<tr><td colspan="7" class="empty">No active alerts</td></tr>';
        return;
    }
    tbody.innerHTML = data.map((a) => `
        <tr>
            <td>${formatTime(a.timestamp)}</td>
            <td><span class="severity severity-${a.severity}">${a.severity}</span></td>
            <td>${a.alert_type}</td>
            <td>${a.source_ip || "-"}</td>
            <td>${a.country || "-"}</td>
            <td>${a.message}</td>
            <td><button class="btn btn-sm" onclick="acknowledgeAlert(${a.id})">Ack</button></td>
        </tr>
    `).join("");
}

async function refreshDNS() {
    const data = await fetchJSON("/api/dns?limit=20");
    const tbody = document.getElementById("dns-body");
    if (!data.length) {
        tbody.innerHTML = '<tr><td colspan="6" class="empty">No DNS queries</td></tr>';
        return;
    }
    tbody.innerHTML = data.map((d) => `
        <tr>
            <td>${formatTime(d.timestamp)}</td>
            <td>${d.src_ip}</td>
            <td>${d.src_country || "-"}</td>
            <td>${d.query_name}</td>
            <td>${d.query_type}</td>
            <td class="${d.is_suspicious ? "tag-suspicious" : "tag-normal"}">
                ${d.is_suspicious ? "Suspicious" : "Normal"}
            </td>
        </tr>
    `).join("");
}

async function refreshLogins() {
    const data = await fetchJSON("/api/login-attempts?limit=20&failed=true");
    const tbody = document.getElementById("logins-body");
    if (!data.length) {
        tbody.innerHTML = '<tr><td colspan="6" class="empty">No failed logins detected</td></tr>';
        return;
    }
    tbody.innerHTML = data.map((l) => `
        <tr>
            <td>${formatTime(l.timestamp)}</td>
            <td>${l.src_ip}</td>
            <td>${l.country || "-"}</td>
            <td>${l.dst_ip}</td>
            <td>${l.service}</td>
            <td>${l.dst_port}</td>
        </tr>
    `).join("");
}

async function refreshPackets() {
    const data = await fetchJSON("/api/packets?limit=30");
    const tbody = document.getElementById("packets-body");
    if (!data.length) {
        tbody.innerHTML = '<tr><td colspan="8" class="empty">No packets captured</td></tr>';
        return;
    }
    tbody.innerHTML = data.map((p) => `
        <tr>
            <td>${formatTime(p.timestamp)}</td>
            <td>${p.src_ip}</td>
            <td>${p.src_country || "-"}</td>
            <td>${p.dst_ip}</td>
            <td>${p.dst_country || "-"}</td>
            <td>${p.protocol}</td>
            <td>${p.src_port || "-"} \u2192 ${p.dst_port || "-"}</td>
            <td>${formatBytes(p.length)}</td>
        </tr>
    `).join("");
}

async function refreshCaptureStatus() {
    const data = await fetchJSON("/api/capture/status");
    updateCaptureStatus(data.running);
}

async function acknowledgeAlert(id) {
    await fetchJSON(`/api/alerts/${id}/acknowledge`, { method: "POST" });
    refreshAlerts();
    refreshStats();
}

// ── Export ──────────────────────────────────────────────────────────

document.getElementById("btn-export").addEventListener("click", () => {
    document.getElementById("export-menu").classList.toggle("show");
});

document.getElementById("export-menu").addEventListener("click", async (e) => {
    e.preventDefault();
    const link = e.target.closest("a");
    if (!link) return;

    const exportType = link.dataset.export;
    const dataType = link.dataset.type;
    document.getElementById("export-menu").classList.remove("show");

    const token = getToken();
    let url;
    if (exportType === "pdf") {
        url = "/api/export/pdf?days=7";
    } else {
        url = `/api/export/csv/${dataType}`;
    }

    const res = await fetch(url, { headers: { Authorization: `Bearer ${token}` } });
    const blob = await res.blob();
    const filename = res.headers.get("Content-Disposition")?.match(/filename=(.+)/)?.[1]
        || `export.${exportType}`;
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = filename;
    a.click();
});

// Close dropdown on outside click
document.addEventListener("click", (e) => {
    if (!e.target.closest(".export-dropdown")) {
        document.getElementById("export-menu").classList.remove("show");
    }
});

// ── Capture Controls ────────────────────────────────────────────────

document.getElementById("btn-start").addEventListener("click", async () => {
    await fetchJSON("/api/capture/start", { method: "POST" });
    refreshCaptureStatus();
});

document.getElementById("btn-stop").addEventListener("click", async () => {
    await fetchJSON("/api/capture/stop", { method: "POST" });
    refreshCaptureStatus();
});

// ── Refresh Loop ────────────────────────────────────────────────────

async function refreshAll() {
    if (!isAuthenticated()) return;
    await Promise.all([
        refreshStats(),
        refreshTopIPs(),
        refreshAlerts(),
        refreshDNS(),
        refreshLogins(),
        refreshPackets(),
        refreshCaptureStatus(),
    ]);
}

function startRefresh() {
    refreshAll();
    if (refreshTimer) clearInterval(refreshTimer);
    refreshTimer = setInterval(refreshAll, REFRESH_INTERVAL);
}

function stopRefresh() {
    if (refreshTimer) clearInterval(refreshTimer);
}

// ── Init ────────────────────────────────────────────────────────────

function initDashboard() {
    initTheme();
    bindAuthEvents();

    if (isAuthenticated()) {
        hideLogin();
        const logoutButton = document.getElementById("btn-logout");
        if (logoutButton) {
            logoutButton.style.display = "inline-block";
        }
        startRefresh();
    } else {
        showLogin();
    }
}

if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", initDashboard);
} else {
    initDashboard();
}
