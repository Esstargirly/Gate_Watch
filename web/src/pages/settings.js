// Settings: notifications, AI (on-device model), and your audit log.
import { enableOnDeviceAI, getOnDeviceStatus, getPreferOnDevice, setPreferOnDevice } from "../ai.js";
import { state } from "../store.js";
import { SEV, SEVERITIES, bus, empty, fmtDateTime, getNotifPrefs, html, icon, setNotifPrefs } from "../ui.js";

let tab = "notifications";
let status = "unavailable";
let progress = null; // null | 0..1 while the model downloads
let aiError = "";

const TABS = [
  ["notifications", "notifications", "NOTIFICATIONS"],
  ["ai", "memory", "AI"],
  ["audit", "history", "AUDIT"],
];

export function mount(params) {
  tab = TABS.some(([k]) => k === params[0]) ? params[0] : "notifications";
  getOnDeviceStatus().then((s) => { status = s; bus.render(); });
}

const toggle = (on, action) => html`<button data-action="${action}" role="switch" aria-checked="${on ? "true" : "false"}" class="w-10 h-5 ${on ? "bg-secondary-container justify-end" : "bg-surface-container-high justify-start"} p-0.5 flex items-center shrink-0 cursor-pointer"><span class="w-4 h-4 ${on ? "bg-on-secondary-fixed" : "bg-outline"} block"></span></button>`;

function notificationsPane() {
  const p = getNotifPrefs();
  return html`
  <section class="flex flex-col gap-space-md">
    <div class="flex items-center gap-1.5">${icon("satellite_alt", "text-primary text-[18px]")}<h2 class="font-headline-md text-headline-md tracking-tight uppercase text-on-surface">Alert notifications</h2></div>
    <div class="bg-surface-container-low p-space-md flex flex-col gap-space-sm">
      <div class="flex items-center justify-between"><div class="flex items-center gap-space-xs">${icon("mobile_friendly", "text-[16px] text-primary")}<span class="font-code-lg text-code-lg text-on-surface font-semibold uppercase">In-app alerts</span></div>${toggle(p.inApp, "toggleInApp")}</div>
      <p class="font-body-sm text-body-sm text-on-surface-variant">A pop-up appears while GateWatch is open when a new alert arrives. This setting is saved in this browser.</p>
      <label class="flex items-center justify-between bg-surface-container-lowest p-space-xs"><span class="font-label-sm text-label-sm text-outline uppercase">Minimum severity:</span>
        <select data-change="minSeverity" class="bg-surface-container text-primary font-label-sm text-label-sm uppercase px-2 py-1 font-bold focus:outline-none">${[...SEVERITIES].reverse().map((s) => html`<option value="${s}" ${p.minSeverity === s ? "selected" : ""}>${s === "low" ? "All severities" : `${SEV[s].label} and above`}</option>`)}</select></label>
    </div>
    <div class="bg-surface-container-low p-space-md flex flex-col gap-1 opacity-80">
      <div class="flex items-center gap-space-xs">${icon("mark_email_read", "text-[16px] text-outline")}<span class="font-code-lg text-code-lg text-on-surface font-semibold uppercase">Email and webhook</span><span class="bg-surface-container-high text-outline font-label-sm text-label-sm px-1.5 py-0.5 font-bold">COMING SOON</span></div>
      <p class="font-body-sm text-body-sm text-on-surface-variant">The sensor will send these, not the browser, so they keep working when nobody has the dashboard open. They aren't switched on yet.</p>
    </div>
  </section>`;
}

function aiPane() {
  const prefer = getPreferOnDevice();
  const label = { ready: "READY", downloadable: "NOT DOWNLOADED", downloading: "DOWNLOADING", unavailable: "UNAVAILABLE" }[status];
  const dot = status === "ready" ? "bg-secondary-container" : status === "unavailable" ? "bg-outline" : "bg-primary-container";
  const pct = progress == null ? 0 : Math.round(progress * 100);
  return html`
  <section class="flex flex-col gap-space-md">
    <div class="flex items-center gap-1.5">${icon("neurology", "text-secondary-fixed text-[18px]")}<h2 class="font-headline-md text-headline-md tracking-tight uppercase text-on-surface">AI assistant</h2></div>
    <div class="bg-surface-container-low p-space-md flex items-center justify-between gap-space-md">
      <div class="flex flex-col min-w-0"><span class="font-code-lg text-code-lg text-on-surface font-semibold uppercase">Prefer on-device AI</span>
        <span class="font-body-sm text-body-sm text-on-surface-variant leading-relaxed">Answer on this computer when the local model is ready, so alert data stays on your device.</span></div>
      ${toggle(prefer, "togglePrefer")}
    </div>
    <div class="bg-surface-container p-space-md flex flex-col gap-space-md">
      <div class="flex items-center justify-between flex-wrap gap-space-xs">
        <div class="flex items-center gap-1 px-1.5 py-0.5 bg-surface-container-lowest text-secondary-fixed">${icon("memory", "text-[13px]")}<span class="font-label-sm text-label-sm font-bold tracking-tight">ON-DEVICE MODEL (GEMINI NANO IN CHROME)</span></div>
        <div class="flex items-center gap-1.5 bg-surface-container-lowest px-2 py-0.5"><span class="w-2 h-2 ${dot}"></span><span class="font-label-sm text-label-sm text-secondary-fixed font-bold tracking-widest">STATUS: ${label}</span></div>
      </div>
      ${status === "downloading" || progress != null ? html`<div class="bg-surface-container-low p-space-sm flex flex-col gap-1.5">
        <div class="flex items-center justify-between font-label-sm text-label-sm"><span class="text-on-surface uppercase font-bold flex items-center gap-1">${icon("download", "text-[12px] text-primary")}Downloading model</span><span id="ai-pct" class="text-secondary-fixed font-bold">${pct}%</span></div>
        <div class="w-full h-2 bg-surface-container-lowest overflow-hidden"><div id="ai-bar" class="h-full bg-secondary-container" style="width:${pct}%"></div></div>
        <span class="font-code-sm text-code-sm text-outline">The first download can take several minutes. Keep this tab open.</span></div>` : ""}
      ${aiError ? html`<p class="font-body-md text-body-md text-error">${aiError}</p>` : ""}
      ${status === "unavailable" ? html`<p class="font-body-sm text-body-sm text-on-surface-variant">The on-device model needs desktop Chrome 139 or newer with the Prompt API turned on in <span class="font-code-sm text-code-sm text-primary">chrome://flags</span>. Until then GateWatch uses the cloud model.</p>` : ""}
      <button data-action="enable" ${status === "ready" || progress != null ? "disabled" : ""} class="w-full h-9 bg-secondary-container text-on-secondary font-label-md text-label-md font-bold uppercase tracking-wider flex items-center justify-center gap-1.5 disabled:opacity-50">
        ${icon("sync_saved_locally", "text-[16px]")}${status === "ready" ? "ON-DEVICE AI IS READY" : progress != null ? "DOWNLOADING..." : "ENABLE ON-DEVICE AI"}</button>
      <div class="bg-surface-container-lowest p-space-sm flex items-start gap-space-sm">${icon("info", "text-primary-container text-[18px] shrink-0 mt-0.5")}
        <div class="flex flex-col gap-1 min-w-0"><span class="font-body-sm text-body-sm text-on-surface leading-tight">When on-device AI isn't available, requests fall back to the cloud.</span>
          <span class="inline-flex items-center gap-1 px-1.5 py-0.5 bg-primary-container/20 text-primary w-fit">${icon("cloud", "text-[12px]")}<span class="font-label-sm text-label-sm font-bold tracking-tight">CLOUD FALLBACK</span></span></div></div>
    </div>
  </section>`;
}

function auditPane() {
  return html`
  <section class="flex flex-col gap-space-md">
    <div class="flex items-center justify-between"><div class="flex items-center gap-1.5">${icon("verified_user", "text-primary text-[18px]")}<h2 class="font-headline-md text-headline-md tracking-tight uppercase text-on-surface">Audit log</h2></div><span class="font-label-sm text-label-sm text-secondary-fixed bg-surface-container-lowest px-1.5 py-0.5">APPEND-ONLY</span></div>
    ${!state.loaded.audit ? html`<div class="h-20 bg-surface-container-low animate-pulse"></div>` : state.audit.length ? html`<div class="flex flex-col gap-1 bg-surface-container-lowest p-space-xs">${state.audit.map((e) => html`
      <div class="bg-surface-container-low p-space-sm flex flex-col gap-1">
        <div class="flex items-center justify-between font-label-sm text-label-sm"><span class="text-secondary-fixed font-bold">${e.action}</span><span class="text-outline">${fmtDateTime(e.timestamp)}</span></div>
        <p class="font-code-sm text-code-sm text-on-surface leading-tight"><span class="text-primary font-bold">${e.actorEmail}</span> • ${e.targetType} <span class="text-secondary-fixed bg-surface-container px-1">${String(e.targetId).slice(0, 40)}</span></p>
        ${e.details && Object.keys(e.details).length ? html`<div class="font-label-sm text-label-sm text-outline break-words">${Object.entries(e.details).filter(([, v]) => v != null && typeof v !== "object").map(([k, v]) => `${k}: ${v}`).join(" • ")}</div>` : ""}
      </div>`)}</div>` : empty("Nothing logged yet", "Status changes, notes and blocklist edits are recorded here.", "history")}
  </section>`;
}

export function render() {
  return html`
  <div class="flex flex-col gap-space-md max-w-3xl mx-auto">
    <div class="flex items-center gap-space-xs py-space-sm"><span class="w-1.5 h-3 bg-primary-container"></span><span class="font-label-sm text-label-sm tracking-wider text-outline uppercase">// GW-SOC :: SETTINGS</span></div>
    <div class="w-full bg-surface-container-lowest p-space-xs overflow-x-auto no-scrollbar"><div class="flex items-center gap-space-xs min-w-max">
      ${TABS.map(([key, ic, label]) => html`<button data-action="tab" data-tab="${key}" class="px-space-md py-1.5 font-label-md text-label-md uppercase tracking-wider flex items-center gap-1.5 ${tab === key ? "text-on-secondary-container bg-secondary-container" : "text-on-surface-variant hover:text-on-surface bg-surface-container-low"}">${icon(ic, "text-[14px]")}${label}</button>`)}
    </div></div>
    ${tab === "ai" ? aiPane() : tab === "audit" ? auditPane() : notificationsPane()}
  </div>`;
}

export const handlers = {
  tab(el) { tab = el.dataset.tab; },
  toggleInApp() { const p = getNotifPrefs(); setNotifPrefs({ ...p, inApp: !p.inApp }); },
  togglePrefer() { setPreferOnDevice(!getPreferOnDevice()); window.dispatchEvent(new Event("gw-ai-status")); },
  async enable() {
    aiError = "";
    progress = 0;
    bus.render();
    const res = await enableOnDeviceAI((f) => {
      progress = f;
      const bar = document.getElementById("ai-bar");
      const pct = document.getElementById("ai-pct");
      if (bar) bar.style.width = `${Math.round(f * 100)}%`;
      if (pct) pct.textContent = `${Math.round(f * 100)}%`;
    });
    status = res.status;
    aiError = res.error || "";
    progress = null;
    window.dispatchEvent(new Event("gw-ai-status"));
    bus.render();
  },
};

export const changes = {
  minSeverity(v) { setNotifPrefs({ ...getNotifPrefs(), minSeverity: v }); },
};