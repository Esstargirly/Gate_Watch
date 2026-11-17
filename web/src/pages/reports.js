// Reports: numbers and charts for a time range, exports, and an AI written summary.
import { friendlyError, summarizeAlerts } from "../ai.js";
import { deviceById, state } from "../store.js";
import {
  SEV, SEVERITIES, aiBadge, bucketCounts, bus, countBy, downloadCsv, empty, fmtDate, fmtNum, html, icon, methodLabel,
  polyline, serviceName, shortId, skeleton, STATUS, toast, typeLabel,
} from "../ui.js";

const DAY = 86400000;
const RANGES = {
  daily: { label: "DAILY", title: "24 HOURS", ms: DAY, buckets: 24 },
  weekly: { label: "WEEKLY", title: "7 DAYS", ms: 7 * DAY, buckets: 7 },
  monthly: { label: "MONTHLY", title: "30 DAYS", ms: 30 * DAY, buckets: 30 },
};
let range = "weekly";
let ai = { text: "", mode: null, loading: false, ms: null, error: "" };

function data() {
  const r = RANGES[range];
  const end = Date.now();
  const start = end - r.ms;
  const inRange = (a, from, to) => a.detectedAt && a.detectedAt.getTime() >= from && a.detectedAt.getTime() <= to;
  const rows = state.alerts.filter((a) => inRange(a, start, end));
  const prev = state.alerts.filter((a) => inRange(a, start - r.ms, start)).length;
  return { r, start, end, rows, prev };
}

const card = (title, ic, body, right = "") => html`<div class="bg-surface-container-lowest p-space-sm flex flex-col gap-space-xs shadow-md">
  <div class="flex items-center justify-between"><div class="flex items-center gap-1.5">${icon(ic, "text-[15px] text-primary")}<span class="font-code-sm text-code-sm font-semibold tracking-wide text-secondary uppercase">${title}</span></div>${right}</div>${body}</div>`;

const rankRows = (items, fmt) => items.length
  ? html`<div class="flex flex-col gap-1">${items.map(([label, n]) => html`<div class="flex items-center justify-between p-1 bg-surface-container-low font-code-sm text-code-sm gap-2"><span class="text-secondary truncate">${label}</span><span class="text-secondary-fixed font-bold flex-shrink-0">${fmt(n)}</span></div>`)}</div>`
  : html`<p class="font-body-sm text-body-sm text-outline">No data in this range.</p>`;

export function render() {
  const { r, start, end, rows, prev } = data();
  const total = rows.length;
  const resolved = rows.filter((a) => a.status === "resolved").length;
  const fp = rows.filter((a) => a.status === "false_positive").length;
  const blocked = state.watchlist.filter((w) => w.blocked).length;
  const delta = prev ? Math.round(((total - prev) / prev) * 100) : null;
  const series = bucketCounts(rows, (a) => a.detectedAt, start, end, r.buckets);
  const peakIdx = series.indexOf(Math.max(...series, 0));
  const pct = (n) => (total ? Math.round((n / total) * 100) : 0);
  const bySev = SEVERITIES.map((s) => [s, rows.filter((a) => a.severity === s).length]);
  const byType = countBy(rows, (a) => a.type).map(([t, n]) => [typeLabel(t), n]);
  const maxType = byType[0] ? byType[0][1] : 1;
  const attackers = countBy(rows, (a) => (a.srcIp && a.srcIp !== "multiple" ? a.srcIp : null)).slice(0, 5);
  const targets = countBy(rows, (a) => deviceById(a.deviceId)?.name || a.dstIp).slice(0, 5);
  const ports = countBy(rows, (a) => a.dstPort).slice(0, 4);

  return html`
  <div class="flex flex-col gap-space-md">
    <div class="flex flex-col gap-space-xs bg-surface-container-lowest p-space-md shadow-md">
      <div class="flex items-center gap-1.5"><span class="w-1.5 h-1.5 bg-secondary-container"></span><span class="font-code-sm text-code-sm text-secondary-fixed tracking-wider uppercase">// GW-SOC :: INCIDENT_REPORTS</span></div>
      <div class="no-print grid grid-cols-3 gap-1 bg-surface-container-low p-0.5 mt-space-xs md:max-w-md">
        ${Object.entries(RANGES).map(([k, v]) => html`<button data-action="range" data-range="${k}" class="py-1 text-center font-code-sm text-code-sm uppercase ${range === k ? "bg-primary-container text-on-primary-container font-semibold" : "text-on-surface-variant hover:text-on-surface"}">${v.label}</button>`)}
      </div>
      <div class="flex items-center justify-between gap-space-xs flex-wrap">
        <span class="flex items-center gap-1.5 px-space-sm py-1.5 bg-surface-container font-code-sm text-code-sm text-on-surface">${icon("calendar_today", "text-[15px] text-primary")}${fmtDate(new Date(start)).toUpperCase()} – ${fmtDate(new Date(end)).toUpperCase()}</span>
        <div class="no-print flex items-center gap-1">
          <button data-action="print" class="flex items-center gap-1 px-2 py-1.5 bg-surface-container-low text-primary hover:bg-primary hover:text-on-primary font-code-sm text-code-sm uppercase">${icon("picture_as_pdf", "text-[14px]")}<span>PDF</span></button>
          <button data-action="csv" class="flex items-center gap-1 px-2 py-1.5 bg-surface-container-low text-primary hover:bg-primary hover:text-on-primary font-code-sm text-code-sm uppercase">${icon("table_chart", "text-[14px]")}<span>CSV</span></button>
        </div>
      </div>
      <p class="font-body-sm text-body-sm text-outline">Based on the latest ${fmtNum(state.alerts.length)} alerts GateWatch has loaded.</p>
    </div>

    ${!state.loaded.alerts ? skeleton(3) : html`
    <div class="grid grid-cols-2 md:grid-cols-4 gap-space-xs">
      <div class="bg-surface-container-lowest p-space-sm shadow-sm"><div class="flex justify-between text-on-surface-variant"><span class="font-label-sm text-label-sm uppercase tracking-wider">TOTAL THREATS</span>${delta == null ? "" : html`<span class="font-label-sm text-label-sm font-bold ${delta > 0 ? "text-error" : "text-secondary-fixed"}">${delta > 0 ? "+" : ""}${delta}%</span>`}</div>
        <div class="flex items-baseline justify-between mt-1"><span class="font-headline-lg text-headline-lg font-bold text-secondary">${fmtNum(total)}</span>
        <svg class="w-14 h-5 overflow-visible text-secondary-fixed" fill="none" viewBox="0 0 50 20"><polyline points="${polyline(series, 50, 20)}" stroke="currentColor" stroke-width="1.5"></polyline></svg></div>
        <div class="mt-1 font-label-sm text-label-sm text-outline">PREVIOUS PERIOD: ${fmtNum(prev)}</div></div>
      <div class="bg-surface-container-lowest p-space-sm shadow-sm"><div class="flex justify-between text-on-surface-variant"><span class="font-label-sm text-label-sm uppercase tracking-wider">RESOLVED</span><span class="font-label-sm text-label-sm text-primary">${pct(resolved)}%</span></div>
        <div class="mt-1 font-headline-lg text-headline-lg font-bold text-secondary">${fmtNum(resolved)}</div><div class="mt-1 w-full bg-surface-container-low h-1"><div class="bg-secondary-container h-full" style="width:${pct(resolved)}%"></div></div></div>
      <div class="bg-surface-container-lowest p-space-sm shadow-sm"><div class="flex justify-between text-on-surface-variant"><span class="font-label-sm text-label-sm uppercase tracking-wider">FALSE POSITIVES</span><span class="font-label-sm text-label-sm text-outline">${pct(fp)}%</span></div>
        <div class="mt-1 font-headline-lg text-headline-lg font-bold text-secondary">${fmtNum(fp)}</div><div class="mt-1 font-label-sm text-label-sm text-outline">OF ${fmtNum(total)} ALERTS</div></div>
      <div class="bg-surface-container-lowest p-space-sm shadow-sm"><div class="flex justify-between text-on-surface-variant"><span class="font-label-sm text-label-sm uppercase tracking-wider">BLOCKLISTED IPS</span><span class="font-label-sm text-label-sm text-primary">NOW</span></div>
        <div class="mt-1 font-headline-lg text-headline-lg font-bold text-secondary">${fmtNum(blocked)}</div><div class="mt-1 font-label-sm text-label-sm text-outline">OF ${state.watchlist.length} WATCHLISTED</div></div>
    </div>

    <div class="grid gap-space-md md:grid-cols-2">
      ${card(`Threats over time (${r.title})`, "timeline", html`
        ${total ? html`<div class="w-full h-36 bg-surface-container-low relative"><svg class="w-full h-full text-secondary-fixed" preserveAspectRatio="none" viewBox="0 0 340 120">
          <line stroke="#353535" stroke-dasharray="2 2" x1="0" x2="340" y1="30" y2="30"></line><line stroke="#353535" stroke-dasharray="2 2" x1="0" x2="340" y1="60" y2="60"></line><line stroke="#353535" stroke-dasharray="2 2" x1="0" x2="340" y1="90" y2="90"></line>
          <polygon fill="currentColor" opacity="0.15" points="0,120 ${polyline(series, 340, 120, 6)} 340,120"></polygon>
          <polyline fill="none" stroke="currentColor" stroke-width="2" vector-effect="non-scaling-stroke" points="${polyline(series, 340, 120, 6)}"></polyline></svg></div>
          <div class="flex justify-between font-label-sm text-label-sm text-outline"><span>${fmtDate(new Date(start))}</span><span class="text-secondary-fixed font-bold">PEAK: ${Math.max(...series)} ALERTS</span><span>${fmtDate(new Date(end))}</span></div>`
          : html`<p class="font-body-sm text-body-sm text-outline py-6 text-center">No alerts in this range.</p>`}`)}
      ${card("Alerts by severity", "pie_chart", html`
        <div class="w-full h-3 bg-surface-container-low flex gap-0.5 mt-1 overflow-hidden">${bySev.map(([s, n]) => html`<div class="${SEV[s].bar} h-full" style="width:${pct(n)}%" title="${SEV[s].label}: ${n}"></div>`)}</div>
        <div class="grid grid-cols-4 gap-1 mt-1">${bySev.map(([s, n]) => html`<div class="bg-surface-container-low p-1 flex flex-col"><div class="flex items-center gap-1"><span class="w-1.5 h-1.5 ${SEV[s].dot}"></span><span class="${SEV[s].text} font-label-sm text-label-sm uppercase">${SEV[s].short}</span></div><span class="font-code-sm text-code-sm text-secondary font-bold mt-0.5">${pct(n)}% (${n})</span></div>`)}</div>`,
        html`<span class="font-label-sm text-label-sm text-on-surface-variant">${fmtNum(total)} EVENTS</span>`)}
    </div>

    <div class="grid gap-space-md md:grid-cols-2">
      ${card("Alerts by type", "bar_chart", byType.length ? html`<div class="flex flex-col gap-2 mt-1">${byType.map(([label, n]) => html`<div class="flex flex-col gap-0.5"><div class="flex items-center justify-between font-code-sm text-code-sm"><span class="text-secondary font-semibold">${label}</span><span class="text-secondary-fixed font-bold">${pct(n)}% (${n})</span></div><div class="w-full h-1.5 bg-surface-container-low"><div class="h-full bg-primary-container" style="width:${(n / maxType) * 100}%"></div></div></div>`)}</div>` : html`<p class="font-body-sm text-body-sm text-outline">No data in this range.</p>`)}
      <div class="flex flex-col gap-space-md">
        ${card("Top attacker IPs", "public", rankRows(attackers, (n) => `${n} alerts`))}
        ${card("Most targeted devices", "dns", rankRows(targets, (n) => `${n} ALERTS`))}
        ${card("Top targeted ports", "lan", ports.length ? html`<div class="grid grid-cols-2 gap-1">${ports.map(([p, n]) => html`<div class="bg-surface-container-low p-1.5 flex flex-col"><span class="text-outline font-label-sm text-label-sm">PORT ${p} ${serviceName(p)}</span><span class="text-secondary-fixed font-bold font-headline-md text-headline-md mt-1">${pct(n)}%</span></div>`)}</div>` : html`<p class="font-body-sm text-body-sm text-outline">No data in this range.</p>`)}
      </div>
    </div>

    <div class="flex flex-col gap-space-xs">
      <button data-action="summary" ${ai.loading || !total ? "disabled" : ""} class="no-print w-full py-2.5 px-space-md bg-surface-container-low hover:bg-surface-container text-primary font-code-sm text-code-sm uppercase tracking-wider flex items-center justify-center gap-2 disabled:opacity-50">
        ${icon("cloud_sync", "text-[18px] text-primary")}<span class="font-bold">${ai.loading ? "GENERATING..." : "GENERATE AI REPORT SUMMARY"}</span>
      </button>
      ${ai.text || ai.loading || ai.error ? html`
      <div class="bg-surface-container-lowest p-space-md flex flex-col gap-space-xs shadow-md">
        <div class="flex items-center justify-between"><div class="flex items-center gap-2">${ai.mode ? aiBadge(ai.mode) : ""}<span class="font-code-sm text-code-sm font-semibold text-secondary uppercase tracking-tight">AI report summary • ${r.title}</span></div>${ai.ms ? html`<span class="font-code-sm text-code-sm text-outline">${(ai.ms / 1000).toFixed(1)}s</span>` : ""}</div>
        <div class="bg-surface-container-low p-space-sm font-body-md text-body-md leading-relaxed text-on-surface">
          ${ai.error ? html`<span class="text-error">${ai.error}</span>` : html`<span id="rep-ai" class="whitespace-pre-wrap">${ai.text || "Writing..."}</span>`}
        </div>
        ${ai.mode ? html`<div class="font-body-sm text-body-sm text-outline">Long summaries are written by the cloud model, so alert details from this range were sent to it. The summary only uses the data in this report.</div>` : ""}
        ${ai.text && !ai.loading ? html`<button data-action="copy" class="no-print self-start px-2 py-1 bg-surface-container-high text-on-surface font-code-sm text-code-sm flex items-center gap-1 uppercase">${icon("content_copy", "text-[13px]")}<span>Copy summary</span></button>` : ""}
      </div>` : ""}
    </div>`}
  </div>`;
}

export const handlers = {
  range(el) { range = el.dataset.range; ai = { text: "", mode: null, loading: false, ms: null, error: "" }; },
  print() { window.print(); },
  csv() {
    const { rows } = data();
    if (!rows.length) { toast("No alerts in this range to export."); return; }
    downloadCsv(`gatewatch-report-${range}-${new Date().toISOString().slice(0, 10)}.csv`,
      ["Event ID", "Detected at", "Severity", "Type", "Source IP", "Destination IP", "Port", "Method", "Status", "Times seen", "What happened"],
      rows.map((a) => [shortId(a.id), a.detectedAt, a.severity, typeLabel(a.type), a.srcIp, a.dstIp, a.dstPort ?? "", methodLabel(a.detectionMethod), STATUS[a.status]?.label || a.status, a.count || 1, a.description]));
    toast(`Exported ${rows.length} alerts`, "ok");
  },
  copy() {
    if (ai.text && navigator.clipboard) navigator.clipboard.writeText(ai.text).then(() => toast("Copied", "ok"));
  },
  async summary() {
    if (ai.loading) return;
    const { r, rows } = data();
    if (!rows.length) return;
    ai = { text: "", mode: null, loading: true, ms: null, error: "" };
    const t0 = performance.now();
    try {
      const res = await summarizeAlerts(rows, `the last ${r.title.toLowerCase()}`, {
        long: true,
        onToken: (_p, full) => {
          ai.text = full;
          const el = document.getElementById("rep-ai");
          if (el) el.textContent = full;
        },
      });
      ai = { text: res.text, mode: res.mode, loading: false, ms: Math.round(performance.now() - t0), error: "" };
    } catch (e) {
      ai = { ...ai, loading: false, error: friendlyError(e) };
    }
    bus.render();
  },
};