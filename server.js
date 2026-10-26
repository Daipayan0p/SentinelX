"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const express = require("express");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const app = express();
const PORT = Number(process.env.PORT) || 5001;
const HOST = process.env.HOST || "0.0.0.0";
const LOG_DIR = path.join(process.cwd(), "logs");
const ALERT_FILE = path.join(LOG_DIR, "alerts.jsonl");
const PUBLIC_DIR = path.join(process.cwd(), "public");
fs.mkdirSync(LOG_DIR, { recursive: true });
app.use(express.json({ limit: "20mb" }));
app.use(express.static(PUBLIC_DIR));
const jsonlFiles = () => fs.readdirSync(LOG_DIR)
    .filter((file) => file.endsWith(".jsonl") && file !== "alerts.jsonl")
    .sort()
    .map((file) => path.join(LOG_DIR, file));
const readJsonl = (file) => {
    if (!fs.existsSync(file))
        return [];
    return fs.readFileSync(file, "utf8").split("\n").filter(Boolean).flatMap((line) => {
        try {
            return [JSON.parse(line)];
        }
        catch {
            return [];
        }
    });
};
const allEvents = () => jsonlFiles().flatMap((file) => readJsonl(file));
const stableId = (value) => crypto.createHash("sha256").update(value).digest("hex").slice(0, 24);
const normalize = (stored) => {
    const event = stored.event;
    const text = [event.message, JSON.stringify(event.eventData || {}), event.channel, event.provider]
        .filter(Boolean).join(" ").toLowerCase();
    const powershell = text.includes("powershell");
    const category = powershell ? "powershell" : event.channel?.toLowerCase().includes("security") ? "authentication" :
        event.channel?.toLowerCase().includes("defender") ? "defense" : "system";
    const action = event.eventId === 4104 ? "script_block" : event.eventId === 4688 ? "process_created" :
        event.eventId === 4624 ? "logon_success" : event.eventId === 4625 ? "logon_failure" : "event_logged";
    return { ...stored, category, action, severity: event.level || "Information", searchableText: text };
};
const detect = (event) => {
    const text = event.searchableText;
    const matches = [];
    const add = (ruleId, title, description, severity, tactic, technique) => {
        matches.push({ ruleId, title, description, severity, agentId: event.agentId, hostname: event.hostname, eventId: event.id,
            timestamp: event.event.timeCreated || event.receivedAt, tactic, technique });
    };
    if (event.event.eventId === 4104 && /(encodedcommand|frombase64string|downloadstring|invoke-webrequest|iex\s|invoke-expression|bypass|hidden)/i.test(text)) {
        add("PS-SUSPICIOUS", "Suspicious PowerShell script", "PowerShell script content contains a download, obfuscation, or execution indicator.", "high", "Execution", "T1059.001");
    }
    if (event.event.eventId === 1102 || text.includes("audit log was cleared")) {
        add("LOG-CLEARED", "Windows audit log cleared", "The Windows security audit log was cleared.", "high", "Defense Evasion", "T1070.001");
    }
    if (event.event.eventId === 7045 || text.includes("service was installed")) {
        add("NEW-SERVICE", "New Windows service installed", "A Windows service installation was recorded.", "medium", "Persistence", "T1543.003");
    }
    if (event.event.eventId === 4698 || text.includes("scheduled task was created")) {
        add("NEW-TASK", "Scheduled task created", "A scheduled task was created and may provide persistence.", "medium", "Persistence", "T1053.005");
    }
    if (event.event.eventId === 4720 || text.includes("user account was created")) {
        add("NEW-ACCOUNT", "New user account created", "A new Windows user account was created.", "high", "Persistence", "T1136.001");
    }
    if (event.event.eventId === 4625) {
        add("FAILED-LOGON", "Failed Windows logon", "A failed logon was recorded. Investigate repeated failures or unusual sources.", "low", "Credential Access", "T1110");
    }
    return matches;
};
const existingAlertIds = () => new Set(readJsonl(ALERT_FILE).map((alert) => alert.id));
const processEvent = (stored) => {
    const event = normalize(stored);
    const known = existingAlertIds();
    const alerts = detect(event).map((match) => ({ ...match, id: stableId(`${match.ruleId}:${event.id}`), createdAt: new Date().toISOString(), status: "open" }))
        .filter((alert) => !known.has(alert.id));
    if (alerts.length)
        fs.appendFileSync(ALERT_FILE, `${alerts.map((alert) => JSON.stringify(alert)).join("\n")}\n`);
    return alerts;
};
const ensureHistoricalDetections = () => {
    const known = existingAlertIds();
    for (const stored of allEvents()) {
        const event = normalize(stored);
        const alerts = detect(event).map((match) => ({ ...match, id: stableId(`${match.ruleId}:${event.id}`), createdAt: new Date().toISOString(), status: "open" }))
            .filter((alert) => !known.has(alert.id));
        if (alerts.length) {
            fs.appendFileSync(ALERT_FILE, `${alerts.map((alert) => JSON.stringify(alert)).join("\n")}\n`);
            alerts.forEach((alert) => known.add(alert.id));
        }
    }
};
const queryParam = (value) => typeof value === "string" ? value : "";
app.get("/", (_req, res) => res.sendFile(path.join(PUBLIC_DIR, "index.html")));
app.get("/health", (_req, res) => res.json({ status: "healthy", service: "SentinelServer", timestamp: new Date().toISOString() }));
app.post("/api/logs", (req, res) => {
    const payload = req.body;
    const configuredKey = process.env.INGEST_API_KEY;
    if (configuredKey && req.header("x-api-key") !== configuredKey)
        return res.status(401).json({ error: "Invalid agent API key" });
    if (!payload?.agentId || !payload.hostname || !Array.isArray(payload.logs))
        return res.status(400).json({ error: "Invalid SentinelAgent payload" });
    const agentId = payload.agentId;
    const hostname = payload.hostname;
    const receivedAt = new Date().toISOString();
    const date = receivedAt.slice(0, 10);
    const events = payload.logs.map((event) => ({
        id: stableId(`${agentId}:${event.recordId || ""}:${event.timeCreated || receivedAt}:${event.eventId || ""}:${event.message || ""}`),
        receivedAt, agentId, hostname,
        operatingSystem: payload.operatingSystem || "Windows", event: { ...event, agentId, hostname }
    }));
    const file = path.join(LOG_DIR, `${date}.jsonl`);
    fs.appendFileSync(file, `${events.map((event) => JSON.stringify({ receivedAt, agentId: event.agentId, hostname: event.hostname, operatingSystem: event.operatingSystem, event: event.event })).join("\n")}\n`);
    events.forEach(processEvent);
    return res.json({ success: true, received: events.length, agentId, hostname, timestamp: receivedAt });
});
app.get("/api/stats", (_req, res) => {
    const events = allEvents().map(normalize);
    const alerts = readJsonl(ALERT_FILE);
    res.json({ events: events.length, alerts: alerts.length, openAlerts: alerts.filter((alert) => alert.status === "open").length,
        criticalAlerts: alerts.filter((alert) => alert.severity === "critical" && alert.status === "open").length,
        hosts: new Set(events.map((event) => event.hostname)).size, lastEvent: events.at(-1)?.event.timeCreated || null });
});
app.get("/api/events", (req, res) => {
    const search = queryParam(req.query.search).toLowerCase();
    const hostname = queryParam(req.query.hostname);
    const limit = Math.min(Math.max(Number(req.query.limit) || 100, 1), 500);
    const events = allEvents().map(normalize).reverse().filter((event) => (!hostname || event.hostname === hostname) && (!search || event.searchableText.includes(search))).slice(0, limit);
    res.json({ events, total: events.length });
});
app.get("/api/alerts", (req, res) => {
    const status = queryParam(req.query.status);
    const alerts = readJsonl(ALERT_FILE).reverse().filter((alert) => !status || alert.status === status);
    res.json({ alerts, total: alerts.length });
});
app.patch("/api/alerts/:id", (req, res) => {
    const allowed = ["open", "acknowledged", "resolved", "false_positive"];
    const status = typeof req.body?.status === "string" ? req.body.status : "";
    if (!allowed.includes(status))
        return res.status(400).json({ error: "Invalid alert status" });
    const alerts = readJsonl(ALERT_FILE).map((alert) => alert.id === req.params.id ? { ...alert, status: status } : alert);
    fs.writeFileSync(ALERT_FILE, alerts.map((alert) => JSON.stringify(alert)).join("\n") + (alerts.length ? "\n" : ""));
    res.json({ success: true });
});
app.get("/api/agents", (_req, res) => {
    const events = allEvents();
    const agents = [...new Map(events.map((event) => [event.agentId, event])).values()].map((last) => ({
        agentId: last.agentId, hostname: last.hostname, operatingSystem: last.operatingSystem,
        lastSeen: last.event.timeCreated || last.receivedAt, eventCount: events.filter((event) => event.agentId === last.agentId).length
    }));
    res.json({ agents });
});
ensureHistoricalDetections();
app.listen(PORT, HOST, () => console.log(`Sentinel MVP listening on http://${HOST}:${PORT}`));
//# sourceMappingURL=server.js.map