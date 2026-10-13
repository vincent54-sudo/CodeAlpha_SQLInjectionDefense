const capabilityHeader = "x-capability-code";
let dashboardData = null;
let csrfToken = "";

function byId(id) {
    return document.getElementById(id);
}

function setResult(element, message, isError = false) {
    element.textContent = message;
    element.hidden = false;
    element.classList.toggle("is-error", isError);
}

async function sendJson(url, capability, body) {
    const response = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json", [capabilityHeader]: capability },
        body: JSON.stringify(body),
        cache: "no-store"
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) {
        throw new Error(data.detail || `Request failed (${response.status})`);
    }
    return data;
}

function setBusy(button, busy, originalText) {
    button.disabled = busy;
    button.setAttribute("aria-busy", String(busy));
    if (busy) button.dataset.originalText = button.textContent;
    button.textContent = busy ? "Working..." : originalText;
}

function showView(name) {
    document.querySelectorAll("[data-view]").forEach((panel) => {
        panel.hidden = panel.dataset.view !== name;
    });
    document.querySelectorAll("[data-view-target]").forEach((button) => {
        const active = button.dataset.viewTarget === name;
        button.classList.toggle("is-active", active);
        if (active) button.setAttribute("aria-current", "page");
        else button.removeAttribute("aria-current");
    });
    const current = byId("breadcrumbCurrent");
    if (current) {
        const labelMap = {
            operations: "DATA OPERATIONS",
            monitor: "SECURITY OPERATIONS",
            help: "HELP & GUIDANCE"
        };
        current.textContent = labelMap[name] || "DATA OPERATIONS";
    }
    if (name === "monitor" && dashboardData) drawActivityChart();
    closeMobileNavigation();
}

function closeMobileNavigation() {
    const sidebar = byId("sidebar");
    const toggle = byId("menuToggle");
    const backdrop = byId("sidebarBackdrop");
    sidebar?.classList.remove("is-open");
    backdrop?.classList.remove("is-visible");
    toggle?.setAttribute("aria-expanded", "false");
    toggle?.setAttribute("aria-label", "Open navigation");
}

function initializeNavigation() {
    document.querySelectorAll("[data-view-target]").forEach((button) => {
        button.addEventListener("click", () => showView(button.dataset.viewTarget));
    });
    document.querySelectorAll("[data-view-link]").forEach((link) => {
        link.addEventListener("click", (event) => {
            event.preventDefault();
            showView(link.dataset.viewLink);
        });
    });
    byId("menuToggle")?.addEventListener("click", (event) => {
        const toggle = event.currentTarget;
        const open = toggle.getAttribute("aria-expanded") !== "true";
        byId("sidebar")?.classList.toggle("is-open", open);
        byId("sidebarBackdrop")?.classList.toggle("is-visible", open);
        toggle.setAttribute("aria-expanded", String(open));
        toggle.setAttribute("aria-label", open ? "Close navigation" : "Open navigation");
    });
    byId("sidebarBackdrop")?.addEventListener("click", closeMobileNavigation);
    document.querySelectorAll("[data-reveal]").forEach((button) => {
        button.addEventListener("click", () => {
            const input = byId(button.dataset.reveal);
            const reveal = input.type === "password";
            input.type = reveal ? "text" : "password";
            button.textContent = reveal ? "Hide" : "Show";
            button.setAttribute("aria-label", `${reveal ? "Hide" : "Show"} capability`);
        });
    });
    if (location.hash === "#monitor") showView("monitor");
}

async function checkApiStatus() {
    const apiStatus = byId("apiStatus");
    try {
        const response = await fetch("/healthz", { cache: "no-store" });
        const payload = await response.json().catch(() => ({}));
        const healthy = response.ok && (payload.status || "degraded") !== "degraded";
        const text = healthy ? "Ready" : "Unavailable";
        apiStatus.textContent = text;
        apiStatus.classList.toggle("is-degraded", !healthy);
    } catch (error) {
        apiStatus.textContent = "Unavailable";
        apiStatus.classList.add("is-degraded");
    }
}

function renderHelp(data) {
    const helpContent = byId("helpContent");
    const helpTasks = byId("helpTasks");
    if (!helpContent || !helpTasks) return;
    helpContent.innerHTML = `
        <p class="help-intro">${data.plain_language}</p>
        <div class="help-steps">
            ${data.steps.map((step) => `
                <article class="help-step">
                    <h3>${step.title}</h3>
                    <p>${step.detail}</p>
                </article>
            `).join("")}
        </div>
        <div class="help-example-box">
            <h3>Common examples</h3>
            <div class="help-examples">
                ${data.examples.map((entry) => `
                    <div class="help-example">
                        <span>${entry.label}</span>
                        <code>${entry.example}</code>
                    </div>
                `).join("")}
            </div>
        </div>
    `;

    helpTasks.innerHTML = data.common_tasks.map((task) => `
        <div class="help-task-item">
            <span class="task-number">${data.common_tasks.indexOf(task) + 1}</span>
            <div>
                <h3>${task.label}</h3>
                <p>${task.detail}</p>
            </div>
        </div>
    `).join("");
}

async function loadHelp() {
    try {
        const response = await fetch("/secure/help", { cache: "no-store" });
        const data = await response.json().catch(() => ({}));
        if (!response.ok) throw new Error(data.detail || "Help guide unavailable");
        renderHelp(data);
    } catch (error) {
        byId("helpContent").innerHTML = `<p class="help-intro">Help is available, but the guide could not load right now.</p>`;
    }
}

function initializeOperations() {
    const storeForm = byId("storeForm");
    storeForm?.addEventListener("submit", async (event) => {
        event.preventDefault();
        const button = storeForm.querySelector("button[type=submit]");
        const result = byId("storeResult");
        setBusy(button, true, "Encrypt and store");
        try {
            const data = await sendJson("/secure/store", byId("clientCapability").value, {
                username: byId("storeUsername").value.trim(),
                sensitive_credential: byId("storeCredential").value
            });
            setResult(result, `${data.message}\nAlgorithm: ${data.encryption_algorithm}`);
            byId("storeCredential").value = "";
        } catch (error) {
            setResult(result, error.message, true);
        } finally {
            setBusy(button, false, "Encrypt and store");
        }
    });

    const retrieveForm = byId("retrieveForm");
    retrieveForm?.addEventListener("submit", async (event) => {
        event.preventDefault();
        const button = retrieveForm.querySelector("button[type=submit]");
        const result = byId("retrieveResult");
        setBusy(button, true, "Inspect request");
        try {
            const data = await sendJson("/secure/retrieve", byId("clientCapability").value, {
                username: byId("searchUsername").value.trim()
            });
            const lines = [data.message || data.status];
            if (data.username) lines.push(`Username: ${data.username}`, `Credential: ${data.decrypted_plain_text}`);
            if (data.alerts?.length) lines.push(`Alerts: ${data.alerts.join(", ")}`);
            setResult(result, lines.join("\n"), data.status === "Blocked");
        } catch (error) {
            setResult(result, error.message, true);
        } finally {
            setBusy(button, false, "Inspect request");
        }
    });
}

function addTableRow(table, values, classes = []) {
    const row = document.createElement("tr");
    values.forEach((value, index) => {
        const cell = document.createElement("td");
        cell.textContent = value ?? "—";
        if (classes[index]) cell.className = classes[index];
        row.append(cell);
    });
    table.append(row);
}

function renderEvents(logs) {
    const table = byId("eventsTable");
    table.replaceChildren();
    if (!logs.length) {
        const row = document.createElement("tr");
        const cell = document.createElement("td");
        cell.className = "empty-cell";
        cell.colSpan = 5;
        cell.textContent = "No security events recorded.";
        row.append(cell);
        table.append(row);
        return;
    }
    logs.forEach((log) => {
        const row = document.createElement("tr");
        const event = document.createElement("td");
        event.textContent = log.pattern || log.event_type || "Security event";
        row.append(event);
        const status = document.createElement("td");
        status.textContent = log.status || "—";
        row.append(status);
        const severity = document.createElement("td");
        const badge = document.createElement("span");
        badge.className = `severity severity-${(log.severity || "info").toLowerCase()}`;
        badge.textContent = log.severity || "info";
        severity.append(badge);
        row.append(severity);
        const ip = document.createElement("td");
        ip.textContent = log.source_ip || "—";
        row.append(ip);
        const time = document.createElement("td");
        time.textContent = log.timestamp ? new Date(log.timestamp).toLocaleString() : "—";
        row.append(time);
        table.append(row);
    });
}

function renderIps(ips) {
    const list = byId("suspiciousIps");
    list.replaceChildren();
    if (!ips.length) {
        const empty = document.createElement("p");
        empty.className = "empty-copy";
        empty.textContent = "No elevated activity recorded.";
        list.append(empty);
        return;
    }
    ips.forEach(({ ip, events }) => {
        const row = document.createElement("div");
        row.className = "ip-row";
        const address = document.createElement("code");
        address.textContent = ip;
        const count = document.createElement("span");
        count.textContent = `${events} events`;
        row.append(address, count);
        list.append(row);
    });
}

function renderUsers(users) {
    const table = byId("usersTable");
    table.replaceChildren();
    if (!users.length) {
        const row = document.createElement("tr");
        const cell = document.createElement("td");
        cell.className = "empty-cell";
        cell.colSpan = 3;
        cell.textContent = "No protected records found.";
        row.append(cell);
        table.append(row);
        return;
    }
    users.forEach((user) => addTableRow(table, [String(user.id), user.username, "Encrypted at rest"]));
}

function renderCloudChecks(cloudSecurity) {
    const container = byId("cloudChecks");
    container.replaceChildren();
    const entries = [
        ["Application security", cloudSecurity.application_security],
        ["Database security", cloudSecurity.database_security],
        ["Encryption", cloudSecurity.encryption],
        ["Authentication", cloudSecurity.authentication],
        ["API security", cloudSecurity.api_security],
        ["Cloud provider", cloudSecurity.cloud_provider]
    ];
    entries.forEach(([name, status]) => {
        const item = document.createElement("div");
        item.className = "cloud-check";
        const label = document.createElement("span");
        label.className = "cloud-check-label";
        label.textContent = name;
        const value = document.createElement("strong");
        value.className = status === "Not integrated" || status === "Setup required" ? "check-pending" : "check-ready";
        value.textContent = status;
        item.append(label, value);
        container.append(item);
    });
}

function renderIncidents(logs) {
    const incidentLogs = logs.filter((log) => log.event_type !== "request_monitored" && (log.risk_score >= 65 || ["sql_injection", "suspicious_login", "unauthorized_access", "rate_limit"].includes(log.event_type)));
    const table = byId("incidentTable");
    table.replaceChildren();
    byId("incidentCount").textContent = `${incidentLogs.length} incidents`;
    byId("statIncidents").textContent = incidentLogs.filter((log) => !log.resolved).length;
    if (!incidentLogs.length) {
        const row = document.createElement("tr");
        const cell = document.createElement("td");
        cell.className = "empty-cell";
        cell.colSpan = 6;
        cell.textContent = "No incidents recorded.";
        row.append(cell);
        table.append(row);
        return;
    }

    incidentLogs.forEach((log) => {
        const row = document.createElement("tr");
        const eventCell = document.createElement("td");
        eventCell.textContent = log.event_type.replaceAll("_", " ");
        eventCell.className = "incident-name";
        const riskCell = document.createElement("td");
        const risk = document.createElement("span");
        risk.className = `severity severity-${log.risk_level.toLowerCase()}`;
        risk.textContent = `${log.risk_level} · ${log.risk_score}`;
        riskCell.append(risk);
        const sourceCell = document.createElement("td");
        sourceCell.textContent = `${log.source_ip || "Unknown source"}\n${log.timestamp ? new Date(log.timestamp).toLocaleString() : "—"}`;
        const reasonCell = document.createElement("td");
        reasonCell.textContent = log.reason;
        const notesCell = document.createElement("td");
        const notes = document.createElement("textarea");
        notes.className = "incident-notes";
        notes.maxLength = 4000;
        notes.value = log.notes || "";
        notes.setAttribute("aria-label", `Investigation notes for incident ${log.id}`);
        notesCell.append(notes);
        const stateCell = document.createElement("td");
        const state = document.createElement("label");
        state.className = "incident-state";
        const resolved = document.createElement("input");
        resolved.type = "checkbox";
        resolved.checked = Boolean(log.resolved);
        resolved.setAttribute("aria-label", `Mark incident ${log.id} resolved`);
        const stateText = document.createElement("span");
        stateText.textContent = log.resolved ? "Resolved" : "Open";
        const save = document.createElement("button");
        save.className = "button button-outline incident-save";
        save.type = "button";
        save.textContent = "Save";
        save.addEventListener("click", async () => {
            save.disabled = true;
            try {
                const response = await fetch(`/secure/admin/incidents/${log.id}`, {
                    method: "PATCH",
                    headers: { "Content-Type": "application/json", "x-csrf-token": csrfToken },
                    body: JSON.stringify({ notes: notes.value, resolved: resolved.checked }),
                    cache: "no-store"
                });
                if (!response.ok) throw new Error("Incident update failed.");
                stateText.textContent = resolved.checked ? "Resolved" : "Open";
                byId("dashboardStatus").textContent = "Investigation updated";
                await loadDashboard();
            } catch (error) {
                byId("dashboardStatus").textContent = error.message;
            } finally {
                save.disabled = false;
            }
        });
        state.append(resolved, stateText, save);
        stateCell.append(state);
        row.append(eventCell, riskCell, sourceCell, reasonCell, notesCell, stateCell);
        table.append(row);
    });
}

function renderDashboard(data) {
    dashboardData = data;
    byId("statRequests").textContent = data.total_requests_monitored;
    byId("statThreats").textContent = data.total_threat_logs;
    byId("statBlocked").textContent = data.blocked_suspicious_requests;
    byId("statIps").textContent = data.suspicious_ips.length;
    byId("statFailed").textContent = data.failed_authentication_attempts;
    byId("systemStatus").textContent = data.system_status;
    byId("encryptionStatus").textContent = data.encryption_status;
    byId("authStatus").textContent = data.cloud_security.authentication;
    byId("apiSecurityStatus").textContent = data.cloud_security.api_security;
    byId("protectedUsers").textContent = data.total_users;
    byId("databaseActivity").textContent = `${data.database_activity.stored} stored · ${data.database_activity.retrieved} retrieved`;
    byId("eventCount").textContent = `${data.logs.length} events`;
    byId("userCount").textContent = `${data.users.length} shown · ${data.total_users} total`;
    byId("dashboardStatus").textContent = `Updated ${new Date().toLocaleTimeString()}`;
    renderEvents(data.logs);
    renderIps(data.suspicious_ips);
    renderUsers(data.users);
    renderCloudChecks(data.cloud_security);
    renderIncidents(data.logs);
    byId("dashboardContent").hidden = false;
    byId("monitorPlaceholder").hidden = true;
    byId("adminAccess").hidden = true;
    byId("refreshDashboard").disabled = false;
    drawActivityChart();
}

async function loadDashboard() {
    const response = await fetch("/secure/admin/dashboard-data", {
        cache: "no-store"
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(data.detail || `Request failed (${response.status})`);
    renderDashboard(data);
}

function initializeAdmin() {
    const form = byId("adminForm");
    form?.addEventListener("submit", async (event) => {
        event.preventDefault();
        const button = form.querySelector("button[type=submit]");
        setBusy(button, true, "Sign in securely");
        try {
            const response = await fetch("/secure/admin/login", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    username: byId("adminUsername").value.trim(),
                    password: byId("adminPassword").value,
                    totp_code: byId("adminTotp").value
                }),
                cache: "no-store"
            });
            const login = await response.json().catch(() => ({}));
            if (!response.ok) throw new Error(login.detail || "Administrator sign in failed.");
            csrfToken = login.csrf_token;
            byId("adminPassword").value = "";
            byId("adminTotp").value = "";
            await loadDashboard();
        } catch (error) {
            byId("monitorPlaceholder").querySelector("p").textContent = error.message;
        } finally {
            setBusy(button, false, "Sign in securely");
        }
    });
    byId("refreshDashboard")?.addEventListener("click", async () => {
        try {
            await loadDashboard();
        } catch (error) {
            byId("dashboardStatus").textContent = error.message;
        }
    });
    byId("logoutAdmin")?.addEventListener("click", async () => {
        try {
            await fetch("/secure/admin/logout", { method: "POST", headers: { "x-csrf-token": csrfToken }, cache: "no-store" });
        } finally {
            csrfToken = "";
            dashboardData = null;
            byId("dashboardContent").hidden = true;
            byId("adminAccess").hidden = false;
            byId("monitorPlaceholder").hidden = false;
        }
    });
    fetch("/secure/admin/session", { cache: "no-store" }).then(async (response) => {
        if (!response.ok) return;
        const session = await response.json();
        csrfToken = session.csrf_token;
        await loadDashboard();
    }).catch(() => {});
    byId("chartRange")?.addEventListener("change", drawActivityChart);
    byId("rotateKeys")?.addEventListener("click", async () => {
        const button = byId("rotateKeys");
        button.disabled = true;
        try {
            const response = await fetch("/secure/admin/rotate-encryption-key", {
                method: "POST",
                headers: { "x-csrf-token": csrfToken },
                cache: "no-store"
            });
            const result = await response.json().catch(() => ({}));
            if (!response.ok) throw new Error(result.detail || "Key rotation failed.");
            byId("dashboardStatus").textContent = `${result.credential_records_rotated} credentials and ${result.mfa_seeds_rotated} MFA seeds rotated`;
            await loadDashboard();
        } catch (error) {
            byId("dashboardStatus").textContent = error.message;
        } finally {
            button.disabled = false;
        }
    });
    byId("exportLogs")?.addEventListener("click", async () => {
        const button = byId("exportLogs");
        button.disabled = true;
        try {
            const response = await fetch("/secure/admin/export-logs", {
                cache: "no-store"
            });
            if (!response.ok) {
                const data = await response.json().catch(() => ({}));
                throw new Error(data.detail || "Audit export failed.");
            }
            const downloadUrl = URL.createObjectURL(await response.blob());
            const link = document.createElement("a");
            link.href = downloadUrl;
            link.download = "security_audit_logs.csv";
            link.click();
            URL.revokeObjectURL(downloadUrl);
        } catch (error) {
            byId("dashboardStatus").textContent = error.message;
        } finally {
            button.disabled = false;
        }
    });
}

function drawActivityChart() {
    const canvas = byId("activityChart");
    if (!canvas || !dashboardData) return;
    const context = canvas.getContext("2d");
    if (!context) return;
    const bounds = canvas.getBoundingClientRect();
    const pixelRatio = window.devicePixelRatio || 1;
    canvas.width = Math.max(1, Math.floor(bounds.width * pixelRatio));
    canvas.height = Math.max(1, Math.floor(bounds.height * pixelRatio));
    context.scale(pixelRatio, pixelRatio);
    const width = bounds.width;
    const height = bounds.height;
    const range = Number(byId("chartRange")?.value || 7);
    const dateBuckets = new Map(dashboardData.daily_activity.map((entry) => [entry.date, entry]));
    const days = Array.from({ length: range }, (_, index) => {
        const date = new Date();
        date.setUTCHours(0, 0, 0, 0);
        date.setUTCDate(date.getUTCDate() - (range - index - 1));
        const key = date.toISOString().slice(0, 10);
        const entry = dateBuckets.get(key) || { threats: 0, other: 0 };
        return { ...entry, label: date.toLocaleDateString(undefined, { month: "short", day: "numeric", timeZone: "UTC" }) };
    });
    const maxValue = Math.max(1, ...days.map((item) => item.threats + item.other));
    const left = 27;
    const bottom = height - 24;
    const graphHeight = height - 38;
    const groupWidth = (width - left - 5) / range;
    const barWidth = Math.min(20, groupWidth * 0.5);
    context.clearRect(0, 0, width, height);
    context.font = "9px 'IBM Plex Mono', monospace";
    context.textBaseline = "middle";
    for (let line = 0; line <= 2; line += 1) {
        const y = 7 + (graphHeight / 2) * line;
        context.strokeStyle = "#223243";
        context.lineWidth = 1;
        context.beginPath();
        context.moveTo(left, y);
        context.lineTo(width, y);
        context.stroke();
        context.fillStyle = "#8296a9";
        context.textAlign = "left";
        context.fillText(String(Math.ceil(maxValue * (1 - line / 2))), 1, y + 1);
    }
    days.forEach((item, index) => {
        const x = left + index * groupWidth + (groupWidth - barWidth) / 2;
        const threatHeight = (item.threats / maxValue) * (graphHeight - 8);
        const otherHeight = (item.other / maxValue) * (graphHeight - 8);
        context.fillStyle = "#ff5470";
        context.fillRect(x, bottom - threatHeight, barWidth, threatHeight);
        context.fillStyle = "#25d6c5";
        context.fillRect(x, bottom - threatHeight - otherHeight, barWidth, otherHeight);
        if (range === 7 || index % 5 === 0 || index === range - 1) {
            context.fillStyle = "#8296a9";
            context.textAlign = "center";
            context.fillText(item.label, x + barWidth / 2, height - 8);
        }
    });
    canvas.setAttribute("aria-label", `Daily activity for ${range} days. ${days.reduce((sum, item) => sum + item.threats, 0)} SQL injection attempts and ${days.reduce((sum, item) => sum + item.other, 0)} other events in the displayed records.`);
}

initializeNavigation();
initializeOperations();
initializeAdmin();
loadHelp();
checkApiStatus();
initializeAdmin();
fetch("/healthz", { cache: "no-store" }).then(async (response) => {
    const health = await response.json();
    const status = byId("apiStatus");
    status.textContent = response.ok && health.status === "ok" ? "Operational" : "Degraded";
    status.classList.toggle("is-degraded", status.textContent !== "Operational");
}).catch(() => {
    byId("apiStatus").textContent = "Unavailable";
    byId("apiStatus").classList.add("is-degraded");
});
window.setInterval(() => {
    if (csrfToken && !byId("monitorView")?.hidden) loadDashboard().catch(() => {});
}, 30000);
window.addEventListener("resize", () => {
    if (!byId("monitorView")?.hidden) drawActivityChart();
});