// Alerts list (and the Incidents tab, which is the same list limited to alerts
// someone is working on: acknowledged or investigating).
import { explainError, setAlertStatus } from "../actions.js";
import { deviceById, state, watchByIp } from "../store.js";
import {
  OPEN, SEV, SEVERITIES, STATUS, bus, empty, fmtDateTime, html, icon, methodLabel, shortId, skeleton,
  sevBadge, srcLabel, statusBadge, targetOf, timeAgo, toast, typeLabel,
} from "../ui.js";

const ALL_STATUSES = ["new", "acknowledged", "investigating", "resolved", "false_positive"];

function makePage(kind) {
  const incidents = kind === "incidents";
  const statuses = incidents ? ["acknowledged", "investigating"] : ALL_STATUSES;
  let q = "";
  let sev = "all";
  let status = "all";
  let limit = 40;
  const expanded = new Set();

  const haystack = (a) => {
    const dev = deviceById(a.deviceId);
    return [a.type, typeLabel(a.type), srcLabel(a), a.srcIp, a.dstIp, a.dstPort, a.protocol, a.srcCountry, dev?.name, a.description].join(" ").toLowerCase();
  };

  const card = (a) => {
    const dev = deviceById(a.deviceId);
    const listed = watchByIp(a.srcIp);
    const s = SEV[a.severity] || SEV.low;
    const open = expanded.has(a.id);
    return html`
    <article data-action="toggle" data-id="${a.id}" class="group relative bg-surface-container-low p-space-md flex flex-col gap-space-sm hover:bg-surface-container cursor-pointer">
      <div class="flex items-start justify-between gap-space-xs">
        <div class="flex items-center gap-2 min-w-0">${sevBadge(a.severity)}<span class="font-headline-md text-headline-md font-bold text-secondary truncate">${typeLabel(a.type)}</span></div>
        <div class="flex items-center gap-1.5 flex-shrink-0"><span class="font-code-sm text-code-sm text-outline">${timeAgo(a.detectedAt)}</span>${statusBadge(a.status)}</div>
      </div>
      <div class="bg-surface-container-lowest p-space-sm flex flex-col gap-1.5 font-code-sm text-code-sm">
        <div class="flex items-center justify-between gap-2"><span class="text-outline">TARGET:</span><span class="text-secondary font-medium truncate">${dev ? dev.name + " " : ""}<span class="text-primary">(${targetOf(a)})</span></span></div>
        <div class="flex items-center justify-between gap-2"><span class="text-outline">SOURCE IP:</span>
          <span class="flex items-center gap-1 min-w-0"><span class="${s.text} font-medium truncate">${srcLabel(a)}</span>
            ${a.srcCountry ? html`<span class="px-1 bg-surface-container-high text-on-surface-variant font-label-sm text-[9px] uppercase">${a.srcCountry}</span>` : ""}
            ${listed ? html`<span class="text-[9px] px-1 ${listed.blocked ? "bg-error-container text-error" : "bg-surface-container-high text-[#f1c40f]"} font-bold">${listed.blocked ? "BLOCKLISTED" : "WATCHLIST"}</span>` : ""}</span></div>
        <div class="flex items-center justify-between"><span class="text-outline">OCCURRENCE:</span><span class="text-secondary-fixed text-[11px] font-bold">seen ${a.count || 1} time${(a.count || 1) === 1 ? "" : "s"}</span></div>
      </div>
      ${open ? html`
      <div class="flex flex-col gap-1.5 font-code-sm text-code-sm text-on-surface-variant bg-surface-container-high/40 p-2">
        <div><span class="text-outline">WHAT HAPPENED:</span> <span class="text-secondary">${a.description}</span></div>
        <div><span class="text-outline">WHY FLAGGED:</span> <span class="text-secondary">${a.reason}</span></div>
        <div class="flex justify-between gap-2"><span><span class="text-outline">METHOD:</span> <span class="text-secondary">${methodLabel(a.detectionMethod)}</span></span><span><span class="text-outline">DETECTED:</span> <span class="text-secondary">${fmtDateTime(a.detectedAt)}</span></span></div>
      </div>` : ""}
      <div class="flex items-center justify-between pt-1 gap-2">
        <div class="flex items-center gap-1.5 flex-wrap">
          ${a.status === "new"
            ? html`<button data-action="ack" data-id="${a.id}" class="px-2.5 py-1 bg-surface-container-high text-secondary-fixed hover:bg-secondary-container hover:text-on-secondary font-label-sm text-label-sm uppercase font-bold flex items-center gap-1">${icon("check_circle", "text-[13px]")}<span>ACKNOWLEDGE</span></button>`
            : html`<span class="px-2.5 py-1 bg-surface-container-highest text-secondary-fixed font-label-sm text-label-sm uppercase font-bold flex items-center gap-1">${icon("done", "text-[13px]")}<span>${STATUS[a.status]?.label || a.status}</span></span>`}
          ${OPEN.includes(a.status) ? html`<button data-action="resolve" data-id="${a.id}" class="px-2.5 py-1 bg-surface-container text-outline hover:text-secondary font-label-sm text-label-sm uppercase font-bold flex items-center gap-1">${icon("done_all", "text-[13px]")}<span>RESOLVE</span></button>` : ""}
        </div>
        <a href="#/alert/${a.id}" class="flex items-center gap-0.5 font-label-sm text-label-sm text-primary uppercase hover:text-secondary-fixed" title="Open ${shortId(a.id)}">OPEN ${icon("chevron_right", "text-[16px]")}</a>
      </div>
    </article>`;
  };

  return {
    render() {
      const base = state.alerts.filter((a) => statuses.includes(a.status));
      const open = state.alerts.filter((a) => OPEN.includes(a.status));
      const unack = open.filter((a) => a.status === "new").length;
      const needle = q.trim().toLowerCase();
      const rows = base.filter((a) => (sev === "all" || a.severity === sev) && (status === "all" || a.status === status) && (!needle || haystack(a).includes(needle)));
      const count = (s) => base.filter((a) => a.severity === s).length;
      const pill = (action, key, val, label, extra, active) => html`<button data-action="${action}" data-${key}="${val}" class="shrink-0 px-2 py-1 ${active ? "bg-surface-container-highest text-secondary-fixed" : "bg-surface-container text-on-surface-variant hover:text-on-surface"} font-label-sm text-label-sm uppercase font-bold flex items-center gap-1">${label}${extra}</button>`;

      return html`
      <div class="flex flex-col gap-space-md">
        <section class="bg-surface-container-lowest px-margin py-space-sm flex items-baseline justify-between gap-2">
          <span class="font-label-sm text-label-sm uppercase tracking-wider text-secondary-fixed font-bold">// GW-SOC :: ${incidents ? "INCIDENTS" : "ALERTS_LIST"}</span>
          <span class="font-code-md text-code-md text-on-surface-variant">${open.length} OPEN <span class="text-error font-bold">(${unack} NEW)</span></span>
        </section>
        <section class="bg-surface-container-low px-margin py-space-md flex flex-col gap-space-sm">
          <div class="relative flex items-center bg-surface-container-lowest">
            <span class="pl-2.5 pr-1 font-code-sm text-code-sm text-primary font-bold pointer-events-none">gw://</span>
            <input data-input="q" data-keep="q" value="${q}" placeholder="Filter by IP, port, type or device..." class="w-full bg-transparent py-2 pl-1 pr-9 text-on-surface font-code-sm text-code-sm placeholder:text-outline-variant focus:outline-none" />
            <span class="absolute right-2.5 text-outline pointer-events-none">${icon("search", "text-[18px]")}</span>
          </div>
          <div class="w-full overflow-x-auto no-scrollbar flex items-center gap-1.5 py-0.5">
            ${pill("sev", "sev", "all", "ALL", html`<span class="px-1 bg-surface-container-lowest text-[9px] font-code-sm text-secondary-fixed">${base.length}</span>`, sev === "all")}
            ${SEVERITIES.map((s) => pill("sev", "sev", s, html`<span class="w-1.5 h-1.5 ${SEV[s].dot}"></span><span>${SEV[s].short}</span>`, html`<span class="${SEV[s].text} font-code-sm text-[9px]">${count(s)}</span>`, sev === s))}
          </div>
          <div class="w-full overflow-x-auto no-scrollbar flex items-center gap-1.5 py-0.5">
            ${pill("status", "status", "all", "STATE: ALL", "", status === "all")}
            ${statuses.map((s) => pill("status", "status", s, STATUS[s].label, "", status === s))}
          </div>
        </section>
        <div class="flex flex-col gap-space-md">
          ${!state.loaded.alerts ? skeleton(3)
            : rows.length ? html`${rows.slice(0, limit).map(card)}
              ${rows.length > limit ? html`<button data-action="more" class="py-2 bg-surface-container-low text-primary font-label-md text-label-md uppercase font-bold">Show more (${rows.length - limit} left)</button>` : ""}`
            : html`${empty(needle || sev !== "all" || status !== "all" ? "No matching alerts" : incidents ? "No incidents in progress" : "No alerts yet",
                incidents ? "Acknowledge or investigate an alert and it shows up here." : needle || sev !== "all" || status !== "all" ? "Nothing matches the current search and filters." : "When the sensor detects something, it appears here live.", "troubleshoot")}
              ${needle || sev !== "all" || status !== "all" ? html`<button data-action="clear" class="py-2 bg-surface-container-high text-secondary-fixed font-label-sm text-label-sm uppercase font-bold">[CLEAR ALL FILTERS]</button>` : ""}`}
        </div>
      </div>`;
    },
    inputs: { q: (v) => { q = v; limit = 40; return true; } },
    handlers: {
      sev(el) { sev = el.dataset.sev; limit = 40; },
      status(el) { status = el.dataset.status; limit = 40; },
      more() { limit += 40; },
      clear() { q = ""; sev = "all"; status = "all"; },
      toggle(el) { const id = el.dataset.id; expanded.has(id) ? expanded.delete(id) : expanded.add(id); },
      async ack(el) { await change(el.dataset.id, "acknowledged"); },
      async resolve(el) { await change(el.dataset.id, "resolved"); },
    },
  };
}

async function change(id, status) {
  const a = state.alerts.find((x) => x.id === id);
  if (!a) return;
  try {
    await setAlertStatus(a, status);
    toast(status === "resolved" ? "Alert resolved" : "Alert acknowledged", "ok");
  } catch (e) {
    toast(explainError(e), "error");
  }
  bus.render();
}

export const alertsPage = makePage("alerts");
export const incidentsPage = makePage("incidents");