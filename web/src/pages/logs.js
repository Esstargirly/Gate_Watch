import { state } from "../store.js";
import {
  METHODS, SEV, SEVERITIES, TYPES, downloadCsv, empty, fmtDateTime, html, humanKey, icon, methodLabel, shortId,
  skeleton, srcLabel, STATUS, targetOf, toast, typeLabel,
} from "../ui.js";

const RANGES = { "1h": ["Last hour", 3600000], "24h": ["Last 24 hours", 86400000], "7d": ["Last 7 days", 604800000], all: ["All loaded", Infinity] };

let q = "";
let range = "24h";
let type = "all";
let sevs = new Set();
let methods = new Set();
let limit = 50;
const expanded = new Set();

function filtered() {
  const needle = q.trim().toLowerCase();
  const since = RANGES[range][1] === Infinity ? 0 : Date.now() - RANGES[range][1];
  return state.alerts.filter((a) => {
    if (a.detectedAt && a.detectedAt.getTime() < since) return false;
    if (type !== "all" && a.type !== type) return false;
    if (sevs.size && !sevs.has(a.severity)) return false;
    if (methods.size && !methods.has(a.detectionMethod)) return false;
    if (!needle) return true;
    return [shortId(a.id), a.id, a.srcIp, a.dstIp, a.dstPort, a.protocol, typeLabel(a.type), a.description].join(" ").toLowerCase().includes(needle);
  });
}

export function render() {
  const rows = filtered();
  const toggle = (action, key, val, label, on, cls = "") => html`<button data-action="${action}" data-${key}="${val}" class="px-2 py-0.5 shrink-0 font-label-sm text-label-sm font-bold uppercase ${on ? cls || "bg-primary-container/20 text-primary" : "bg-surface-container text-on-surface-variant hover:text-on-surface"}">${label}</button>`;
  return html`
  <div class="flex flex-col gap-space-md">
    <div class="no-print flex flex-col bg-surface-container-lowest p-space-md shadow-md gap-space-md">
      <div class="flex items-center gap-space-xs"><span class="w-1.5 h-1.5 bg-secondary-container animate-pulse"></span><span class="font-label-sm text-label-sm tracking-wider uppercase text-secondary-fixed font-bold">// GW-SOC :: AUDIT &amp; SECURITY_LOGS</span></div>
      <div class="relative flex items-center bg-surface-container-low">
        <span class="font-code-sm text-code-sm text-primary pl-space-sm pr-space-xs select-none">gw-logs://&gt;</span>
        <input data-input="q" data-keep="q" value="${q}" placeholder="Search by event ID, IP, port, protocol or type..." class="w-full bg-transparent py-1.5 pr-8 text-on-surface font-code-sm text-code-sm focus:outline-none placeholder:text-outline/70" />
        ${q ? html`<button data-action="clearq" aria-label="Clear search" class="absolute right-2 text-outline-variant hover:text-on-surface">${icon("close", "text-[16px]")}</button>` : ""}
      </div>
      <div class="grid grid-cols-2 gap-space-xs">
        <label class="flex items-center gap-1 bg-surface-container px-space-sm py-1">${icon("schedule", "text-[14px] text-outline")}
          <select data-change="range" class="bg-transparent text-on-surface font-code-sm text-code-sm w-full focus:outline-none">${Object.entries(RANGES).map(([k, [label]]) => html`<option value="${k}" ${range === k ? "selected" : ""}>${label}</option>`)}</select></label>
        <label class="flex items-center gap-1 bg-surface-container px-space-sm py-1">${icon("filter_alt", "text-[14px] text-outline")}
          <select data-change="type" class="bg-transparent text-on-surface font-code-sm text-code-sm w-full focus:outline-none"><option value="all">All types</option>${Object.entries(TYPES).map(([k, label]) => html`<option value="${k}" ${type === k ? "selected" : ""}>${label}</option>`)}</select></label>
      </div>
      <div class="flex items-center gap-space-xs overflow-x-auto no-scrollbar"><span class="font-label-sm text-label-sm text-outline uppercase shrink-0 mr-1">SEV:</span>
        ${SEVERITIES.map((s) => toggle("sev", "sev", s, SEV[s].short, sevs.has(s), SEV[s].badge))}</div>
      <div class="flex items-center gap-space-xs overflow-x-auto no-scrollbar"><span class="font-label-sm text-label-sm text-outline uppercase shrink-0 mr-1">METH:</span>
        ${Object.entries(METHODS).map(([k, label]) => toggle("method", "method", k, label, methods.has(k)))}</div>
      <div class="flex items-center justify-between gap-space-sm">
        <span class="font-label-sm text-label-sm text-outline">MATCHED: <span class="text-on-surface font-bold">${rows.length} EVENTS</span></span>
        <div class="flex items-center gap-space-xs">
          <button data-action="csv" class="flex items-center gap-1 px-2.5 py-1 bg-surface-container-high text-secondary-fixed font-label-sm text-label-sm font-bold uppercase active:bg-secondary-container active:text-on-secondary-fixed">${icon("table_chart", "text-[13px]")}<span>Export CSV</span></button>
          <button data-action="print" class="flex items-center gap-1 px-2.5 py-1 bg-surface-container-high text-primary font-label-sm text-label-sm font-bold uppercase active:bg-primary-container active:text-on-primary">${icon("picture_as_pdf", "text-[13px]")}<span>Export PDF</span></button>
        </div>
      </div>
    </div>

    ${!state.loaded.alerts ? skeleton(4) : rows.length ? html`
    <div class="flex flex-col gap-0.5">
      <div class="hidden sm:grid grid-cols-12 bg-surface-container px-space-md py-1.5 text-outline font-label-sm text-label-sm uppercase tracking-wider"><div class="col-span-4">EVENT / TIME</div><div class="col-span-5">SOURCE → DESTINATION</div><div class="col-span-3 text-right">METHOD / STATE</div></div>
      ${rows.slice(0, limit).map((a) => {
        const s = SEV[a.severity] || SEV.low;
        const open = expanded.has(a.id);
        return html`<div class="flex flex-col bg-surface-container-low">
          <button data-action="row" data-id="${a.id}" class="w-full text-left p-space-md grid grid-cols-12 items-center gap-1 ${open ? "bg-surface-container-high/40" : ""} active:bg-surface-container-high">
            <div class="col-span-5 sm:col-span-4 flex flex-col min-w-0 pr-1"><div class="flex items-center gap-1.5"><span class="w-2 h-2 shrink-0 ${s.dot}"></span><span class="font-code-sm text-code-sm font-bold ${s.text} truncate">#${shortId(a.id)}</span></div>
              <span class="font-code-sm text-code-sm text-on-surface-variant font-medium truncate">${typeLabel(a.type)}</span><span class="font-code-sm text-[10px] text-outline">${fmtDateTime(a.detectedAt)}</span></div>
            <div class="col-span-4 sm:col-span-5 flex flex-col min-w-0 font-code-sm text-code-sm leading-tight"><span class="text-on-surface truncate">${srcLabel(a)}</span><span class="text-primary truncate">→ ${targetOf(a)}</span><span class="font-label-sm text-[9px] text-outline-variant uppercase">${a.protocol || ""} • seen ${a.count || 1}x</span></div>
            <div class="col-span-3 flex flex-col items-end min-w-0 pl-1"><span class="px-1.5 py-0.5 bg-surface-container text-on-surface-variant font-label-sm text-[9px] uppercase">${methodLabel(a.detectionMethod)}</span><span class="font-label-sm text-label-sm ${STATUS[a.status]?.cls.split(" ").pop() || "text-outline"} uppercase font-bold mt-1 tracking-tight text-right">${STATUS[a.status]?.label || a.status}</span></div>
          </button>
          ${open ? html`<div class="flex flex-col bg-surface-container-lowest p-space-md gap-space-sm shadow-inner">
            <div class="bg-surface-container-low p-space-sm"><span class="font-label-sm text-label-sm text-outline uppercase tracking-wider">// WHAT HAPPENED</span><p class="font-body-sm text-body-sm text-on-surface mt-1">${a.description}</p></div>
            <div class="bg-surface-container-low p-space-sm"><span class="font-label-sm text-label-sm text-outline uppercase tracking-wider">// WHY IT WAS FLAGGED</span><p class="font-body-sm text-body-sm text-on-surface-variant mt-1">${a.reason}</p></div>
            ${Object.keys(a.evidence || {}).length ? html`<div class="bg-surface-container-low p-space-sm"><span class="font-label-sm text-label-sm text-outline uppercase tracking-wider">// EVIDENCE</span>
              <div class="grid grid-cols-2 gap-space-xs mt-1 font-code-sm text-code-sm">${Object.entries(a.evidence).filter(([, v]) => typeof v !== "object" || Array.isArray(v)).map(([k, v]) => html`<div class="bg-surface-container px-2 py-1 min-w-0"><div class="text-outline text-[10px] uppercase truncate">${humanKey(k)}</div><div class="text-on-surface font-bold break-words">${Array.isArray(v) ? v.join(", ") : String(v)}</div></div>`)}</div></div>` : ""}
            <a href="#/alert/${a.id}" class="self-end px-2.5 py-1 bg-primary text-on-primary font-label-sm text-label-sm uppercase font-bold">Open incident</a>
          </div>` : ""}
        </div>`;
      })}
      ${rows.length > limit ? html`<button data-action="more" class="no-print py-2 bg-surface-container-low text-primary font-label-md text-label-md uppercase font-bold">Show more (${rows.length - limit} left)</button>` : ""}
    </div>` : empty("No events match", "Try a wider time range or clear the filters.", "manage_search")}
  </div>`;
}

export const inputs = { q: (v) => { q = v; limit = 50; return true; } };
export const changes = {
  range(v) { range = v; limit = 50; },
  type(v) { type = v; limit = 50; },
};
export const handlers = {
  clearq() { q = ""; },
  sev(el) { const v = el.dataset.sev; sevs.has(v) ? sevs.delete(v) : sevs.add(v); },
  method(el) { const v = el.dataset.method; methods.has(v) ? methods.delete(v) : methods.add(v); },
  row(el) { const id = el.dataset.id; expanded.has(id) ? expanded.delete(id) : expanded.add(id); },
  more() { limit += 50; },
  print() { window.print(); },
  csv() {
    const rows = filtered();
    if (!rows.length) { toast("Nothing to export with the current filters."); return; }
    downloadCsv(`gatewatch-logs-${new Date().toISOString().slice(0, 10)}.csv`,
      ["Event ID", "Detected at", "Severity", "Type", "Source IP", "Destination IP", "Port", "Protocol", "Method", "Status", "Times seen", "What happened", "Why flagged"],
      rows.map((a) => [shortId(a.id), a.detectedAt, a.severity, typeLabel(a.type), a.srcIp, a.dstIp, a.dstPort ?? "", a.protocol ?? "", methodLabel(a.detectionMethod), STATUS[a.status]?.label || a.status, a.count || 1, a.description, a.reason]));
    toast(`Exported ${rows.length} events`, "ok");
  },
};