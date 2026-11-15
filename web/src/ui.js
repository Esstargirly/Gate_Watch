const ESC = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" };
export const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ESC[c]);

class Safe {
  constructor(s) { this.s = s; }
}
const part = (v) =>
  v instanceof Safe ? v.s : Array.isArray(v) ? v.map(part).join("") : v == null || v === false ? "" : esc(v);
export const html = (strings, ...vals) => {
  let out = strings[0];
  vals.forEach((v, i) => { out += part(v) + strings[i + 1]; });
  return new Safe(out);
};
export const raw = (s) => new Safe(String(s));
export const toStr = (v) => (v instanceof Safe ? v.s : String(v ?? ""));

// pages call bus.render() after changing their own state
export const bus = { render() {} };

export const LOGO = "/logo.svg";

// ------------------------------------------------------------------ labels
export const SEVERITIES = ["critical", "high", "medium", "low"];
export const SEV_RANK = { low: 0, medium: 1, high: 2, critical: 3 };
export const SEV = {
  critical: { label: "CRITICAL", short: "CRIT", badge: "bg-error-container text-on-error-container", dot: "bg-error", text: "text-error", bar: "bg-error-container", hex: "#ffb4ab" },
  high: { label: "HIGH", short: "HIGH", badge: "bg-[#4d2500] text-[#ff7a00]", dot: "bg-[#ff7a00]", text: "text-[#ff7a00]", bar: "bg-[#e65100]", hex: "#ff7a00" },
  medium: { label: "MEDIUM", short: "MED", badge: "bg-[#423700] text-[#f1c40f]", dot: "bg-[#f1c40f]", text: "text-[#f1c40f]", bar: "bg-[#fbc02d]", hex: "#f1c40f" },
  low: { label: "LOW", short: "LOW", badge: "bg-primary-container/20 text-primary", dot: "bg-primary", text: "text-primary", bar: "bg-primary-container", hex: "#1e6bff" },
};
export const OPEN = ["new", "acknowledged", "investigating"];
export const STATUS = {
  new: { label: "NEW", cls: "bg-error-container/60 text-error" },
  acknowledged: { label: "ACKNOWLEDGED", cls: "bg-surface-container-high text-primary" },
  investigating: { label: "INVESTIGATING", cls: "bg-surface-container-high text-secondary-fixed" },
  resolved: { label: "RESOLVED", cls: "bg-surface-container-highest text-outline" },
  false_positive: { label: "FALSE POSITIVE", cls: "bg-surface-container-highest text-outline" },
};
export const TYPES = {
  port_scan: "Port Scan", brute_force: "Brute Force", syn_flood: "SYN Flood",
  suspicious_connection: "Suspicious Connection", traffic_spike: "Traffic Spike",
  watchlist_hit: "Watchlist Hit", unknown_device: "Unknown Device",
};
export const METHODS = { rule: "Rule", baseline: "Baseline", threat_intel: "Threat Intel" };
export const typeLabel = (t) => TYPES[t] || String(t || "Unknown");
export const methodLabel = (m) => METHODS[m] || String(m || "Rule");
export const SERVICES = { 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP", 123: "NTP", 443: "HTTPS", 445: "SMB", 1433: "MSSQL", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 8080: "HTTP-alt" };
export const serviceName = (p) => SERVICES[p] || "";

// -------------------------------------------------------------- formatting
export function timeAgo(d) {
  if (!d || !d.getTime) return "–";
  const s = Math.max(0, (Date.now() - d.getTime()) / 1000);
  if (s < 10) return "just now";
  if (s < 60) return `${Math.floor(s)}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}
export const fmtClock = (d) => (d && d.getTime ? d.toTimeString().slice(0, 8) : "–");
export const fmtMs = (d) => (d && d.getTime ? `${fmtClock(d)}.${String(d.getMilliseconds()).padStart(3, "0")}` : "–");
export const fmtDateTime = (d) => (d && d.getTime ? d.toLocaleString([], { dateStyle: "medium", timeStyle: "medium" }) : "–");
export const fmtDate = (d) => (d && d.getTime ? d.toLocaleDateString([], { month: "short", day: "numeric" }) : "–");
export const fmtNum = (n) => Number(n || 0).toLocaleString();
export const fmtBytes = (n) => (n >= 1048576 ? `${(n / 1048576).toFixed(1)} MB` : n >= 1024 ? `${(n / 1024).toFixed(1)} KB` : `${n || 0} B`);
export const shortId = (id) => `GW-${String(id || "").slice(0, 6).toUpperCase()}`;
export const initials = (name) =>
  String(name || "?").split(/[\s@._-]+/).filter(Boolean).slice(0, 2).map((w) => w[0].toUpperCase()).join("") || "?";
export const humanKey = (k) => String(k).replace(/([A-Z])/g, " $1").replace(/^./, (c) => c.toUpperCase());
// the SYN flood rule uses the text "multiple" when there is no single source IP
export const srcLabel = (a) => (a.srcIp === "multiple" ? "Many sources" : a.srcIp);
export const targetOf = (a) => `${a.dstIp || "?"}${a.dstPort ? ":" + a.dstPort : ""}`;
export const ipDocId = (ip) => ip.replace(/\./g, "_").replace(/:/g, "-").replace(/\//g, "_"); // same as schema.py

export function isIp(v) {
  const s = String(v || "");
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(s)) return s.split(".").every((n) => Number(n) <= 255);
  return s.includes(":") && /^[0-9a-f:]+$/i.test(s);
}

export function countBy(arr, fn) {
  const m = new Map();
  arr.forEach((x) => {
    const k = fn(x);
    if (k == null || k === "") return;
    m.set(k, (m.get(k) || 0) + 1);
  });
  return [...m.entries()].sort((a, b) => b[1] - a[1]);
}

export function bucketCounts(items, get, start, end, n) {
  const out = Array(n).fill(0);
  const w = (end - start) / n;
  items.forEach((i) => {
    const d = get(i);
    if (!d || !d.getTime) return;
    const t = d.getTime();
    if (t < start || t > end) return;
    out[Math.min(n - 1, Math.floor((t - start) / w))]++;
  });
  return out;
}

export function polyline(values, w, h, pad = 2) {
  const max = Math.max(1, ...values);
  const step = values.length > 1 ? (w - pad * 2) / (values.length - 1) : 0;
  return values.map((v, i) => `${(pad + i * step).toFixed(1)},${(h - pad - (v / max) * (h - pad * 2)).toFixed(1)}`).join(" ");
}

// ------------------------------------------------------------ components
export const icon = (name, cls = "text-[16px]") => html`<span class="material-symbols-outlined ${cls}">${name}</span>`;

export const sevBadge = (sev) => {
  const s = SEV[sev] || SEV.low;
  return html`<span class="flex items-center gap-1.5 px-2 py-0.5 ${s.badge}"><span class="w-1.5 h-1.5 ${s.dot}"></span><span class="font-label-sm text-label-sm font-bold tracking-wider uppercase">${s.label}</span></span>`;
};
export const statusBadge = (st) => {
  const s = STATUS[st] || STATUS.new;
  return html`<span class="px-1.5 py-0.5 ${s.cls} font-label-sm text-label-sm font-bold uppercase whitespace-nowrap">${s.label}</span>`;
};
// Shown on every AI answer: where it actually ran.
export const aiBadge = (mode) =>
  mode === "on_device"
    ? html`<span class="inline-flex items-center gap-1 px-1.5 py-0.5 bg-surface-container-lowest text-secondary-fixed">${icon("memory", "text-[13px]")}<span class="font-label-sm text-label-sm font-bold tracking-tight">ON-DEVICE</span></span>`
    : html`<span class="inline-flex items-center gap-1 px-1.5 py-0.5 bg-primary-container/20 text-primary">${icon("cloud", "text-[13px]")}<span class="font-label-sm text-label-sm font-bold tracking-tight">CLOUD</span></span>`;

export const empty = (title, text, ic = "inbox") => html`
  <div class="flex flex-col items-center justify-center text-center p-space-xl bg-surface-container-lowest gap-1.5">
    <div class="w-10 h-10 bg-surface-container flex items-center justify-center text-outline">${icon(ic, "text-[24px]")}</div>
    <span class="font-headline-md text-headline-md text-on-surface">${title}</span>
    <span class="font-body-sm text-body-sm text-outline max-w-[300px]">${text}</span>
  </div>`;

export const skeleton = (rows = 3) => html`<div class="flex flex-col gap-1.5 animate-pulse">${Array.from({ length: rows }, () => html`<div class="h-20 bg-surface-container-low"></div>`)}</div>`;

export function toast(message, tone = "info") {
  const box = document.getElementById("toasts");
  if (!box) return;
  const el = document.createElement("div");
  const border = tone === "error" ? "border-error" : tone === "ok" ? "border-secondary-fixed" : "border-primary-container";
  el.className = `px-3 py-2 font-code-sm text-code-sm shadow-lg border-l-2 bg-surface-container-high text-on-surface ${border}`;
  el.textContent = message;
  box.appendChild(el);
  setTimeout(() => el.remove(), 4500);
}

// ------------------------------------------------------ in-app notifications
const NOTIF_KEY = "gw_notif";
export function getNotifPrefs() {
  try {
    return { inApp: true, minSeverity: "high", ...JSON.parse(localStorage.getItem(NOTIF_KEY) || "{}") };
  } catch {
    return { inApp: true, minSeverity: "high" };
  }
}
export function setNotifPrefs(p) {
  try { localStorage.setItem(NOTIF_KEY, JSON.stringify(p)); } catch { /* ignore */ }
}

// -------------------------------------------------------------------- export
const csvCell = (v) => {
  let s = v instanceof Date ? v.toISOString() : String(v ?? "");
  if (/^[=+\-@\t\r]/.test(s)) s = "'" + s; // stops spreadsheet formula injection
  return `"${s.replace(/"/g, '""')}"`;
};
export function downloadCsv(name, headers, rows) {
  const body = [headers, ...rows].map((r) => r.map(csvCell).join(",")).join("\r\n");
  const url = URL.createObjectURL(new Blob(["\ufeff" + body], { type: "text/csv;charset=utf-8" }));
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}