// "More": sensor status, who you are, and links to everything else.
import { logout } from "../auth.js";
import { latestSensor, sensorOnline, state } from "../store.js";
import { fmtNum, html, icon, initials, timeAgo, toast } from "../ui.js";

const row = (href, ic, title, text, badge = "") => html`
  <a href="${href}" class="group flex items-center justify-between p-space-md bg-surface-container-low hover:bg-surface-container-high transition-all">
    <div class="flex items-center gap-space-md min-w-0">
      <div class="w-8 h-8 bg-surface-container-lowest flex items-center justify-center text-primary group-hover:text-secondary-fixed flex-shrink-0">${icon(ic, "text-[20px]")}</div>
      <div class="flex flex-col min-w-0"><div class="flex items-center gap-2"><span class="font-headline-md text-headline-md text-secondary group-hover:text-primary tracking-tight">${title}</span>${badge}</div><span class="font-body-sm text-body-sm text-on-surface-variant truncate">${text}</span></div>
    </div>
    ${icon("chevron_right", "text-[18px] text-outline group-hover:text-secondary-fixed flex-shrink-0 ml-2")}
  </a>`;

export function render() {
  const p = state.profile || {};
  const s = latestSensor();
  const ok = sensorOnline();
  return html`
  <div class="flex flex-col gap-space-md max-w-2xl mx-auto">
    <div class="flex items-center gap-space-xs py-space-sm"><span class="w-1.5 h-1.5 bg-primary-container"></span><span class="font-label-sm text-label-sm text-primary tracking-widest uppercase">// GW-SOC :: NAVIGATION &amp; SYSTEM_INFO</span></div>

    <div class="relative bg-surface-container-low p-space-md overflow-hidden">
      <div class="absolute top-0 left-0 right-0 h-0.5 ${ok ? "bg-secondary-container" : "bg-outline"}"></div>
      <div class="flex items-start justify-between gap-space-sm mb-space-xs">
        <div class="flex flex-col min-w-0"><span class="font-label-sm text-label-sm text-outline uppercase tracking-wider">Sensor</span>
          <h2 class="font-headline-md text-headline-md text-secondary font-bold truncate tracking-tight">${s ? s.name : "No sensor connected"}</h2>
          ${s ? html`<span class="font-code-sm text-code-sm text-primary-fixed-dim">interface: ${s.interface || "unknown"}</span>` : ""}</div>
        <div class="flex items-center gap-1.5 bg-surface-container-lowest px-2 py-1 flex-shrink-0"><span class="relative flex h-2 w-2"><span class="${ok ? "animate-ping bg-secondary-container" : ""} absolute inline-flex h-full w-full opacity-75"></span><span class="relative inline-flex h-2 w-2 ${ok ? "bg-secondary-container" : "bg-outline"}"></span></span>
          <span class="font-label-sm text-label-sm ${ok ? "text-secondary-fixed" : "text-outline"} font-bold tracking-tight">${ok ? "ONLINE" : s ? "OFFLINE" : "WAITING"}</span></div>
      </div>
      <div class="mt-space-sm bg-surface-container-lowest p-space-sm flex flex-col gap-1.5 font-code-sm text-code-sm text-on-surface-variant">
        <div class="flex justify-between"><span>Last heartbeat:</span><span class="text-secondary">${s ? timeAgo(s.lastHeartbeat) : "–"}</span></div>
        <div class="flex justify-between"><span>Packets counted today:</span><span class="text-secondary">${fmtNum(state.statsToday?.packets)}</span></div>
        <div class="flex justify-between"><span>Detection rules:</span><span class="text-secondary">port scan, brute force, SYN flood</span></div>
        ${s?.version ? html`<div class="flex justify-between"><span>Sensor version:</span><span class="text-secondary">${s.version}</span></div>` : ""}
      </div>
      ${!ok ? html`<p class="mt-space-sm font-body-sm text-body-sm text-outline">${s ? "No heartbeat for over 2 minutes. Is the sensor still running?" : "Start the sensor (python main.py) and it will show up here."}</p>` : ""}
    </div>

    <div class="bg-surface-container-low p-space-md flex flex-col gap-space-sm">
      <span class="font-label-sm text-label-sm text-outline uppercase tracking-wider">Connect a sensor</span>
      <p class="font-body-sm text-body-sm text-on-surface-variant">Your data is private to your account. Put this line in the sensor's <span class="font-code-sm text-code-sm text-primary">.env</span> file so it sends its alerts to your workspace:</p>
      <div class="flex items-center gap-2 bg-surface-container-lowest p-space-sm">
        <code class="font-code-sm text-code-sm text-secondary-fixed break-all flex-grow">GATEWATCH_WORKSPACE=${state.workspaceId}</code>
        <button data-action="copyWs" aria-label="Copy" class="flex-shrink-0 text-primary hover:text-secondary-fixed">${icon("content_copy", "text-[18px]")}</button>
      </div>
    </div>

    <div class="bg-surface-container-low p-space-md flex items-center gap-space-md">
      <div class="w-10 h-10 flex-shrink-0 bg-primary-container/30 border border-primary-container/40 flex items-center justify-center font-headline-md text-headline-md font-bold text-on-surface">${initials(p.displayName || p.email)}</div>
      <div class="flex flex-col min-w-0"><span class="font-headline-md text-headline-md text-secondary font-semibold truncate">${p.displayName || "Analyst"}</span>
        <span class="font-body-sm text-body-sm text-on-surface-variant truncate">${p.email}</span>
        <span class="mt-0.5 self-start bg-primary-container/20 text-primary-fixed font-label-sm text-label-sm px-1.5 py-0.5 tracking-tight uppercase font-semibold">WORKSPACE OWNER</span></div>
    </div>

    <div class="flex flex-col gap-1.5">
      <span class="font-label-sm text-label-sm text-outline uppercase tracking-wider px-1">Modules &amp; configuration</span>
      ${row("#/reports", "bar_chart", "Reports", "Daily, weekly and monthly threat statistics")}
      ${row("#/settings/ai", "tune", "Settings", "Notifications, AI preferences and on-device model")}
      ${row("#/intel/devices", "devices", "Devices", "Everything seen on the network, unknown ones flagged")}
      ${row("#/settings/audit", "receipt_long", "Audit log", "Everything you changed, and when")}
    </div>

    <button data-action="signout" class="w-full min-h-[42px] bg-error-container/20 hover:bg-error-container text-error hover:text-on-error flex items-center justify-center gap-space-sm cursor-pointer">
      ${icon("logout", "text-[18px]")}<span class="font-label-md text-label-md uppercase tracking-wider font-bold">[ SIGN OUT ]</span>
    </button>
    <p class="text-center font-code-sm text-code-sm text-outline">GateWatch v0.1</p>
  </div>`;
}

export const handlers = {
  signout() { logout(); },
  copyWs() {
    if (navigator.clipboard) navigator.clipboard.writeText(`GATEWATCH_WORKSPACE=${state.workspaceId}`).then(() => toast("Copied", "ok"));
  },
};