import { latestSensor, sensorOnline, state } from "./store.js";
import { LOGO, SEV, html, icon, initials, srcLabel, timeAgo, typeLabel } from "./ui.js";
import { describeAiStatus } from "./ai.js";

const NAV = [
  ["dashboard", "radar", "DASH"],
  ["alerts", "crisis_alert", "ALERTS"],
  ["incidents", "target", "INCIDENTS"],
  ["logs", "terminal", "LOGS"],
  ["intel", "hub", "INTEL"],
  ["more", "tune", "MORE"],
];

let aiStatus = "unavailable";
let bellOpen = false;
export const setAiStatus = (s) => { aiStatus = s; };
export const closeBell = () => { bellOpen = false; };
export const bellIsOpen = () => bellOpen;

export const shellHtml = () => html`
  <header id="hdr" class="no-print fixed top-0 inset-x-0 z-50 pt-safe bg-surface-container-lowest/95 backdrop-blur-xl shadow-[0_1px_8px_rgba(0,0,0,0.6)]"></header>
  <nav id="nav" class="no-print fixed bottom-0 inset-x-0 z-40 pb-safe bg-surface-container-lowest/95 backdrop-blur-xl shadow-[0_-2px_12px_rgba(0,0,0,0.7)] md:inset-x-auto md:left-0 md:top-14 md:bottom-0 md:w-56 md:pb-0 md:shadow-none md:border-r md:border-outline-variant/30"></nav>
  <main id="page" class="pt-14 pb-20 md:pb-8 md:pl-56 min-h-screen">
    <div id="errors"></div>
    <div id="page-inner" class="max-w-6xl mx-auto p-gutter md:p-margin-lg"></div>
  </main>
  <div id="toasts" class="no-print fixed z-[60] bottom-20 md:bottom-4 right-3 flex flex-col gap-1.5 max-w-[90vw] w-80"></div>`;

export function headerHtml() {
  const p = state.profile;
  const chip = describeAiStatus(aiStatus);
  const lime = chip.tone === "lime";
  const newAlerts = state.alerts.filter((a) => a.status === "new");
  const menu = newAlerts.slice(0, 5);
  return html`
  <div class="h-14 px-gutter md:px-margin-lg flex items-center justify-between gap-space-xs">
    <a href="#/dashboard" class="flex items-center gap-space-sm min-w-0 flex-shrink-0">
      <img alt="GateWatch" class="h-8 w-8 object-contain" src="${LOGO}" />
      <span class="font-headline-md text-headline-md tracking-wider uppercase text-on-surface font-bold">GateWatch</span>
    </a>
    <a href="#/settings/ai" class="hidden xs:flex items-center gap-1.5 px-2 py-1 bg-surface-container-low border ${lime ? "border-secondary-container/40" : "border-primary-container/40"}" title="Where AI answers run">
      <span class="w-1.5 h-1.5 ${lime ? "bg-secondary-container" : "bg-primary-container"} animate-pulse"></span>
      <span class="font-label-sm text-label-sm ${lime ? "text-secondary-fixed" : "text-primary"} font-bold tracking-tight">${chip.label.toUpperCase()}</span>
      ${icon(lime ? "memory" : "cloud", `text-[12px] leading-none ${lime ? "text-secondary-fixed" : "text-primary"}`)}
    </a>
    <div class="flex items-center gap-space-xs flex-shrink-0">
      <div class="relative" id="bell-wrap">
        <button data-action="bell" aria-label="New alerts" class="relative w-11 h-11 flex items-center justify-center text-on-surface-variant hover:text-on-surface active:bg-surface-container-high transition-colors">
          ${icon("notifications", "text-[20px]")}
          ${newAlerts.length ? html`<span class="absolute top-2 right-2 min-w-4 h-4 px-0.5 bg-error-container text-on-error-container font-code-sm text-[10px] flex items-center justify-center font-bold">${newAlerts.length > 99 ? "99+" : newAlerts.length}</span>` : ""}
        </button>
        ${bellOpen ? html`
        <div class="absolute right-0 top-12 w-72 bg-surface-container-high shadow-2xl border border-outline-variant/40">
          <div class="px-3 py-2 font-label-sm text-label-sm text-outline uppercase tracking-wider border-b border-outline-variant/30">// NEW ALERTS (${newAlerts.length})</div>
          ${menu.length ? menu.map((a) => html`
            <a href="#/alert/${a.id}" class="flex items-center justify-between gap-2 px-3 py-2 hover:bg-surface-container-highest">
              <div class="min-w-0"><div class="font-code-md text-code-md text-on-surface truncate">${typeLabel(a.type)}</div><div class="font-code-sm text-code-sm text-outline truncate">${srcLabel(a)} → ${a.dstIp}</div></div>
              <span class="font-code-sm text-code-sm ${(SEV[a.severity] || SEV.low).text} flex-shrink-0">${timeAgo(a.detectedAt)}</span>
            </a>`) : html`<div class="px-3 py-4 font-body-sm text-body-sm text-outline">Nothing new. You're all caught up.</div>`}
          <a href="#/alerts" class="block px-3 py-2 text-center font-label-sm text-label-sm text-primary uppercase border-t border-outline-variant/30 hover:bg-surface-container-highest">View all alerts</a>
        </div>` : ""}
      </div>
      <a href="#/more" class="w-8 h-8 flex items-center justify-center bg-primary-container/30 border border-primary-container/40 font-code-md text-code-md font-bold text-on-surface" title="${p?.displayName || ""}">${initials(p?.displayName || p?.email)}</a>
    </div>
  </div>`;
}

export function navHtml(active) {
  const unread = state.alerts.filter((a) => a.status === "new").length;
  return html`<div class="grid grid-cols-6 h-14 px-space-xs items-stretch md:flex md:flex-col md:h-auto md:p-2 md:gap-1">
    ${NAV.map(([key, ic, label]) => {
      const on = active === key || (key === "alerts" && active === "alert");
      return html`<a href="#/${key}" class="relative flex flex-col items-center justify-center min-h-[44px] transition-colors md:flex-row md:justify-start md:gap-3 md:px-3 md:h-11 ${on ? "text-secondary-fixed bg-surface-container-low" : "text-on-surface-variant hover:text-on-surface md:hover:bg-surface-container-low"}">
        ${icon(ic, "text-[20px]")}
        ${key === "alerts" && unread ? html`<span class="absolute top-1 right-2 min-w-3.5 h-3.5 px-0.5 bg-error-container text-on-error-container font-code-sm text-[9px] flex items-center justify-center font-bold md:static md:ml-auto">${unread > 99 ? "99+" : unread}</span>` : ""}
        <span class="font-label-sm text-label-sm md:text-label-md uppercase tracking-tighter md:tracking-wider mt-0.5 md:mt-0">${label}</span>
        ${on ? html`<span class="absolute bottom-0 left-1/4 right-1/4 h-0.5 bg-primary-container md:hidden"></span>` : ""}
      </a>`;
    })}
    <div class="hidden md:block mt-auto pt-4 px-3 font-code-sm text-code-sm text-outline">
      ${(() => { const s = latestSensor(); return html`<div class="flex items-center gap-1.5"><span class="w-1.5 h-1.5 ${sensorOnline() ? "bg-secondary-fixed" : "bg-outline"}"></span>${s ? s.name : "No sensor yet"}</div>`; })()}
    </div>
  </div>`;
}

// Firestore problems (missing index, permission denied) shown right where you'll see them
export function errorsHtml() {
  const errs = Object.entries(state.errors);
  if (!errs.length) return html``;
  return html`<div class="bg-error-container text-on-error-container px-margin py-space-sm font-code-sm text-code-sm break-words">
    ${errs.map(([k, e]) => html`<div><strong>Couldn't load ${k}:</strong> ${e.code || ""} ${e.message || ""}</div>`)}
  </div>`;
}

export const shellHandlers = {
  bell() { bellOpen = !bellOpen; },
};