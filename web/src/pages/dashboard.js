import { friendlyError, summarizeAlerts } from "../ai.js";
import { openAlerts, sensorOnline, state } from "../store.js";
import {
  OPEN, SEV, SEV_RANK, aiBadge, bucketCounts, bus, countBy, empty, fmtBytes, fmtMs, fmtNum, html, icon,
  polyline, shortId, skeleton, srcLabel, targetOf, timeAgo, toast, typeLabel,
} from "../ui.js";

let paused = false;
let frozen = null;
let proto = "ALL";
let ai = { text: "", mode: null, loading: false, ms: null, error: "" };

const PROTO_COLORS = { TCP: "bg-primary-container", UDP: "bg-primary", DNS: "bg-secondary-container", HTTP: "bg-on-surface-variant" };

const tile = (accent, label, tag, value, right, sub) => html`
  <div class="bg-surface-container-low p-space-sm relative overflow-hidden flex flex-col justify-between shadow-sm">
    <div class="absolute top-0 left-0 right-0 h-[2px] ${accent}"></div>
    <div class="flex items-center justify-between gap-1"><span class="font-label-sm text-label-sm text-on-surface-variant tracking-wider uppercase font-semibold">${label}</span>${tag}</div>
    <div class="flex items-baseline justify-between mt-space-xs"><span class="font-headline-lg text-headline-lg font-bold text-on-surface tracking-tight">${value}</span>${right}</div>
    <div class="font-code-sm text-[10px] text-on-surface-variant mt-0.5">${sub}</div>
  </div>`;

const chip = (cls, text) => html`<span class="font-code-sm text-code-sm ${cls} bg-surface-container-high px-1 py-0.5">${text}</span>`;

function perSecond(packets) {
  const secs = new Map();
  packets.forEach((p) => {
    if (!p.ts || !p.ts.getTime) return;
    const k = Math.floor(p.ts.getTime() / 1000);
    secs.set(k, (secs.get(k) || 0) + 1);
  });
  if (!secs.size) return [];
  const keys = [...secs.keys()];
  const max = Math.max(...keys);
  const min = Math.max(Math.min(...keys), max - 59);
  const out = [];
  for (let k = min; k <= max; k++) out.push(secs.get(k) || 0);
  return out;
}

export function render() {
  const now = Date.now();
  const dayAgo = now - 86400000;
  const alerts = state.alerts;
  const last24 = alerts.filter((a) => a.detectedAt && a.detectedAt.getTime() >= dayAgo);
  const open = openAlerts();
  const crit = open.filter((a) => a.severity === "critical").length;
  const high = open.filter((a) => a.severity === "high").length;
  const unack = open.filter((a) => a.status === "new").length;
  const blocked = state.watchlist.filter((w) => w.blocked).length;
  const online = state.devices.filter((d) => d.status === "online").length;
  const unknown = state.devices.filter((d) => !d.known).length;
  const hourly = bucketCounts(last24, (a) => a.detectedAt, dayAgo, now, 12);
  const ok = sensorOnline();

  const packets = paused && frozen ? frozen : state.traffic;
  const series = perSecond(packets);
  const peak = Math.max(0, ...series);
  const protoCounts = countBy(packets, (p) => p.protocol);
  const alertSrc = new Set(open.map((a) => a.srcIp));
  const shown = packets.filter((p) => proto === "ALL" || p.protocol === proto).slice(0, 12);

  const sources = countBy(alerts, (a) => (a.srcIp && a.srcIp !== "multiple" ? a.srcIp : null)).slice(0, 5);
  const topSrc = sources[0] ? sources[0][1] : 1;
  const queue = [...open].sort((a, b) => (SEV_RANK[b.severity] - SEV_RANK[a.severity]) || ((b.detectedAt?.getTime() || 0) - (a.detectedAt?.getTime() || 0))).slice(0, 3);

  return html`
  <div class="flex flex-col gap-space-md">
    <div class="bg-surface-container-lowest px-gutter py-space-sm flex items-center justify-between gap-2 shadow-sm">
      <div class="flex items-center gap-space-sm min-w-0">
        <span class="relative flex h-2 w-2 flex-shrink-0"><span class="${ok ? "animate-ping bg-secondary-container" : ""} absolute inline-flex h-full w-full rounded-full opacity-75"></span><span class="relative inline-flex rounded-full h-2 w-2 ${ok ? "bg-secondary-container" : "bg-outline"}"></span></span>
        <span class="font-label-sm text-label-sm tracking-tight uppercase truncate ${ok ? "text-secondary-fixed" : "text-outline"}">${ok ? "SENSOR ONLINE" : "SENSOR OFFLINE"} <span class="text-on-surface-variant">•</span> <span class="text-on-surface">${fmtNum(state.statsToday?.packets)} PACKETS TODAY</span></span>
      </div>
      <span class="font-code-sm text-code-sm text-outline flex-shrink-0 hidden xs:block">LIVE</span>
    </div>

    ${!state.loaded.alerts ? skeleton(2) : html`
    <div class="grid grid-cols-2 md:grid-cols-4 gap-space-xs">
      ${tile("bg-primary-container", "Alerts 24h", "", fmtNum(last24.length),
        html`<svg class="w-12 h-5 text-secondary-fixed flex-shrink-0" fill="none" viewBox="0 0 48 20"><polyline points="${polyline(hourly, 48, 20)}" stroke="currentColor" stroke-width="1.75" stroke-linecap="square"></polyline></svg>`,
        `${alerts.length} loaded in total`)}
      ${tile("bg-error-container", "Active Alerts", crit ? html`<span class="flex items-center gap-1"><span class="w-1.5 h-1.5 bg-error animate-pulse"></span><span class="font-code-sm text-code-sm text-error font-bold">${crit} CRIT</span></span>` : "", fmtNum(open.length),
        html`<div class="flex gap-space-xs">${chip("text-error", `Crit ${crit}`)}${chip("text-[#ff7a00]", `High ${high}`)}</div>`,
        `${unack} not yet acknowledged`)}
      ${tile("bg-secondary-container", "Blocklisted IPs", "", fmtNum(blocked), icon("shield", "text-[18px] text-secondary-fixed"), `of ${state.watchlist.length} on the watchlist`)}
      ${tile("bg-primary", "Devices Online", "", `${online}/${state.devices.length}`, "", unknown ? `${unknown} unknown device${unknown > 1 ? "s" : ""}` : "All devices known")}
    </div>`}

    <div class="grid gap-space-md md:grid-cols-2">
      <!-- AI summary -->
      <div class="bg-surface-container-low p-space-md relative overflow-hidden shadow-md flex flex-col gap-space-sm">
        <div class="absolute top-0 left-0 right-0 h-[2px] bg-primary-container"></div>
        <div class="absolute top-0 right-0 w-3 h-3 bg-secondary-container"></div>
        <div class="flex items-center justify-between gap-space-xs">
          <div class="flex items-center gap-space-xs min-w-0">${icon("psychology", "text-[16px] text-primary flex-shrink-0")}<span class="font-label-md text-label-md uppercase tracking-wider text-on-surface font-bold truncate">AI Threat Summary</span></div>
          ${ai.mode ? html`<div class="flex items-center gap-1.5">${aiBadge(ai.mode)}<span class="font-code-sm text-[10px] text-outline">${(ai.ms / 1000).toFixed(1)}s</span></div>` : ""}
        </div>
        <div class="bg-surface-container-lowest p-space-sm shadow-inner min-h-[72px]">
          ${ai.error ? html`<p class="font-body-md text-body-md text-error">${ai.error}</p>`
            : ai.loading || ai.text ? html`<p id="ai-text" class="font-body-md text-body-md text-on-surface leading-snug whitespace-pre-wrap">${ai.text || "Thinking..."}</p>`
            : html`<p class="font-body-md text-body-md text-on-surface-variant">Get a plain-language summary of the last 24 hours (${last24.length} alerts).</p>`}
        </div>
        ${ai.mode ? html`<div class="flex items-center gap-space-xs font-body-sm text-body-sm text-on-surface-variant">${icon(ai.mode === "on_device" ? "verified_user" : "cloud_upload", `text-[13px] ${ai.mode === "on_device" ? "text-secondary-fixed" : "text-primary"}`)}${ai.mode === "on_device" ? "Answered on this device. Your alert data did not leave your browser." : "Answered by the cloud model. Alert data was sent to it for this reply."}</div>` : ""}
        <button data-action="summarize" ${ai.loading || !last24.length ? "disabled" : ""} class="w-full bg-secondary-container text-on-secondary px-space-md py-1.5 flex items-center justify-center gap-space-xs rounded-DEFAULT font-bold uppercase tracking-wider font-label-md text-label-md disabled:opacity-50">
          ${icon("auto_awesome", "text-[16px]")}<span>${ai.loading ? "Generating..." : ai.text ? "Regenerate summary" : "Summarize last 24 hours"}</span>
        </button>
      </div>

      <!-- traffic chart -->
      <div class="bg-surface-container-low p-space-md shadow-sm flex flex-col gap-space-sm">
        <div class="flex items-center justify-between">
          <span class="font-label-md text-label-md uppercase tracking-wider text-on-surface font-bold">Packets per second</span>
          <span class="font-code-sm text-code-sm text-on-surface-variant">sample of ${packets.length} stored</span>
        </div>
        <div class="w-full h-24 bg-surface-container-lowest relative overflow-hidden shadow-inner">
          ${series.length > 1 ? html`
          <svg class="w-full h-full text-primary-container" preserveAspectRatio="none" viewBox="0 0 300 90">
            <polygon fill="currentColor" opacity="0.2" points="0,90 ${polyline(series, 300, 90)} 300,90"></polygon>
            <polyline fill="none" stroke="currentColor" stroke-width="2" vector-effect="non-scaling-stroke" points="${polyline(series, 300, 90)}"></polyline>
          </svg>
          <div class="absolute top-2 right-2 bg-surface-container-high px-1.5 py-0.5 font-code-sm text-[10px] text-secondary-fixed">PEAK: ${fmtNum(peak)}/s</div>`
          : html`<div class="h-full flex items-center justify-center font-code-sm text-code-sm text-outline">Waiting for traffic from the sensor</div>`}
        </div>
        <div class="flex flex-col gap-space-xs">
          <div class="flex items-center justify-between font-code-sm text-code-sm text-on-surface-variant"><span>PROTOCOL SPLIT</span><span class="text-on-surface truncate ml-2">${protoCounts.slice(0, 4).map(([k, v]) => `${k} ${Math.round((v / (packets.length || 1)) * 100)}%`).join(" • ") || "–"}</span></div>
          <div class="w-full h-2 bg-surface-container-lowest flex overflow-hidden">
            ${protoCounts.map(([k, v]) => html`<div class="${PROTO_COLORS[k] || "bg-outline"} h-full" style="width:${(v / (packets.length || 1)) * 100}%"></div>`)}
          </div>
        </div>
      </div>
    </div>

    <!-- packet table -->
    <div class="bg-surface-container-low p-space-md shadow-sm">
      <div class="flex flex-col gap-space-sm mb-space-sm">
        <div class="flex items-center justify-between">
          <div class="flex items-center gap-space-xs">${icon("terminal", "text-[16px] text-primary")}<span class="font-label-md text-label-md uppercase tracking-wider text-on-surface font-bold">Live Packet Stream</span></div>
          <button data-action="pause" class="${paused ? "bg-primary-container text-on-primary" : "bg-surface-container-high text-on-surface"} font-code-sm text-code-sm px-space-sm py-1 flex items-center gap-1">
            ${icon(paused ? "play_arrow" : "pause", "text-[14px] text-secondary-fixed")}<span class="uppercase font-bold">${paused ? "RESUME" : "PAUSE"}</span>
          </button>
        </div>
        <div class="flex items-center gap-1 overflow-x-auto no-scrollbar">
          ${["ALL", "TCP", "UDP", "HTTP", "DNS"].map((p) => html`<button data-action="proto" data-proto="${p}" class="${proto === p ? "bg-primary-container text-on-primary" : "bg-surface-container-high text-on-surface-variant hover:text-on-surface"} font-code-sm text-[10px] px-2 py-0.5 font-bold uppercase">${p}</button>`)}
        </div>
      </div>
      ${!state.loaded.traffic ? skeleton(2) : shown.length ? html`
      <div class="flex flex-col gap-1 font-code-sm text-[11px]">
        ${shown.map((p) => html`
        <div class="p-1.5 ${alertSrc.has(p.srcIp) ? "bg-error-container/20" : "bg-surface-container-lowest"} flex flex-col gap-0.5">
          <div class="flex items-center justify-between text-[10px]"><span class="${alertSrc.has(p.srcIp) ? "text-error" : "text-primary"} font-semibold">${fmtMs(p.ts)}</span>
            <span class="flex items-center gap-1">${alertSrc.has(p.srcIp) ? html`<span class="bg-error text-on-error px-1 font-bold">IN ALERT</span>` : ""}<span class="bg-surface-container-high text-on-surface px-1">${fmtBytes(p.size)}</span></span></div>
          <div class="flex items-center justify-between text-on-surface gap-2"><span class="truncate">${p.srcIp}${p.srcPort ? ":" + p.srcPort : ""} → ${p.dstIp}${p.dstPort ? ":" + p.dstPort : ""}</span><span class="text-primary font-bold flex-shrink-0">${p.protocol}${p.flags ? ` [${p.flags}]` : ""}</span></div>
        </div>`)}
      </div>` : empty("No packets yet", "Start the sensor (or run the simulator with --write) and packets show up here.", "lan")}
    </div>

    <div class="grid gap-space-md md:grid-cols-2">
      <!-- top sources -->
      <div class="bg-surface-container-low p-space-md shadow-sm">
        <div class="flex items-center gap-space-xs mb-space-sm">${icon("public", "text-[16px] text-primary")}<span class="font-label-md text-label-md uppercase tracking-wider text-on-surface font-bold">Top Attack Sources</span></div>
        ${sources.length ? html`<div class="flex flex-col gap-space-xs">${sources.map(([ip, n]) => {
          const country = alerts.find((a) => a.srcIp === ip && a.srcCountry)?.srcCountry;
          return html`<div class="flex items-center gap-space-sm"><span class="font-code-sm text-code-sm text-on-surface w-32 truncate">${ip}</span>
            <div class="flex-grow bg-surface-container-lowest h-2.5 overflow-hidden"><div class="bg-error-container h-full" style="width:${(n / topSrc) * 100}%"></div></div>
            <span class="font-code-sm text-code-sm text-on-surface font-bold w-16 text-right">${country ? html`<span class="text-outline mr-1">${country}</span>` : ""}${n}</span></div>`;
        })}</div>` : html`<p class="font-body-sm text-body-sm text-outline">No sources yet.</p>`}
      </div>

      <!-- incident queue -->
      <div class="bg-surface-container-low p-space-md shadow-sm">
        <div class="flex items-center justify-between mb-space-sm"><div class="flex items-center gap-space-xs">${icon("crisis_alert", "text-[16px] text-error")}<span class="font-label-md text-label-md uppercase tracking-wider text-on-surface font-bold">Incident Queue</span></div><a href="#/alerts" class="font-code-sm text-code-sm text-primary">ALL ALERTS →</a></div>
        ${queue.length ? html`<div class="flex flex-col gap-space-xs">${queue.map((a) => html`
          <div class="bg-surface-container-lowest p-space-sm flex flex-col gap-space-xs relative overflow-hidden">
            <div class="absolute left-0 top-0 bottom-0 w-1 ${(SEV[a.severity] || SEV.low).dot}"></div>
            <div class="flex items-start justify-between gap-space-xs pl-space-xs">
              <div class="flex flex-col min-w-0"><span class="font-code-sm text-[10px] ${(SEV[a.severity] || SEV.low).text} font-bold uppercase tracking-wider">${(SEV[a.severity] || SEV.low).label} • ${shortId(a.id)}</span><span class="font-headline-md text-headline-md font-semibold text-on-surface truncate">${typeLabel(a.type)}</span></div>
              <span class="font-code-sm text-code-sm text-outline flex-shrink-0">${timeAgo(a.detectedAt)}</span>
            </div>
            <div class="pl-space-xs font-code-sm text-[11px] text-on-surface-variant flex justify-between gap-2"><span class="truncate">Target: <span class="text-on-surface">${targetOf(a)}</span></span><span class="truncate">Source: <span class="${(SEV[a.severity] || SEV.low).text}">${srcLabel(a)}</span></span></div>
            <a href="#/alert/${a.id}" class="mt-0.5 w-full bg-surface-container-high text-secondary-fixed font-label-md text-label-md uppercase py-1.5 text-center font-bold hover:bg-secondary-container hover:text-on-secondary">Triage incident</a>
          </div>`)}</div>`
          : state.loaded.alerts ? empty("No open alerts", "Nothing needs attention right now.", "verified_user") : skeleton(1)}
      </div>
    </div>
  </div>`;
}

export const handlers = {
  pause() { paused = !paused; frozen = paused ? [...state.traffic] : null; },
  proto(el) { proto = el.dataset.proto; },
  async summarize() {
    if (ai.loading) return;
    const rows = state.alerts.filter((a) => a.detectedAt && a.detectedAt.getTime() >= Date.now() - 86400000);
    if (!rows.length) { toast("No alerts in the last 24 hours to summarize."); return; }
    ai = { text: "", mode: null, loading: true, ms: null, error: "" };
    const t0 = performance.now();
    try {
      const r = await summarizeAlerts(rows, "the last 24 hours", {
        onToken: (_piece, full) => {
          ai.text = full;
          const el = document.getElementById("ai-text");
          if (el) el.textContent = full;
        },
      });
      ai = { text: r.text, mode: r.mode, loading: false, ms: Math.round(performance.now() - t0), error: "" };
    } catch (e) {
      ai = { ...ai, loading: false, error: friendlyError(e) };
    }
    bus.render();
  },
};