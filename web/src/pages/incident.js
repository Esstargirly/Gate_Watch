import { addNote, blockIp, explainError, setAlertStatus, unblockIp } from "../actions.js";
import { QUICK_ACTIONS, askAboutAlert, explainAlert, friendlyError, runQuickAction, saveAiSummary } from "../ai.js";
import { deviceById, state, watchAlertExtras, watchByIp } from "../store.js";
import {
  SEV, STATUS, aiBadge, bus, empty, fmtClock, fmtDateTime, html, humanKey, icon, isIp, methodLabel,
  serviceName, shortId, skeleton, srcLabel, statusBadge, timeAgo, toast, typeLabel,
} from "../ui.js";

let alertId = null;
let extras = { timeline: [], notes: [] };
let unwatch = null;
let ai = { thread: [], loading: false, label: "", stream: "", error: "" };
let noteText = "";
let chatText = "";
let busy = false;

export function mount(params) {
  alertId = params[0];
  extras = { timeline: [], notes: [] };
  ai = { thread: [], loading: false, label: "", stream: "", error: "" };
  noteText = "";
  chatText = "";
  unwatch = watchAlertExtras(alertId, (kind, data) => {
    extras[kind] = data;
    bus.render();
  });
}
export function unmount() {
  if (unwatch) unwatch();
  unwatch = null;
}

const current = () => state.alerts.find((a) => a.id === alertId);

const evidenceValue = (v) => (Array.isArray(v) ? v.join(", ") : typeof v === "number" ? v.toLocaleString() : String(v));

function aiPanel(a) {
  const cached = !ai.thread.length && a.aiSummary && a.aiSummary.text ? a.aiSummary : null;
  const last = ai.thread[ai.thread.length - 1] || cached;
  const bubble = (q, text, mode, ms) => html`
    <div class="bg-surface-container p-space-md flex flex-col gap-space-xs">
      <div class="flex items-center justify-between gap-2"><span class="font-label-sm text-label-sm text-primary uppercase font-bold tracking-wider truncate">// ${q}</span><span class="flex items-center gap-1.5 flex-shrink-0">${aiBadge(mode)}${ms ? html`<span class="font-code-sm text-[10px] text-outline">${(ms / 1000).toFixed(1)}s</span>` : ""}</span></div>
      <p class="font-body-md text-body-md text-on-surface leading-relaxed whitespace-pre-wrap">${text}</p>
      <div class="flex items-center gap-1 font-body-sm text-body-sm text-on-surface-variant">${icon(mode === "on_device" ? "verified_user" : "cloud_upload", `text-[13px] ${mode === "on_device" ? "text-secondary-fixed" : "text-primary"}`)}${mode === "on_device" ? "Answered on this device. Alert data did not leave your browser." : "Answered by the cloud model. Alert data was sent to it for this reply."}</div>
    </div>`;
  return html`
  <div class="bg-surface-container-low flex flex-col overflow-hidden shadow-xl">
    <div class="bg-surface-container-highest px-margin py-space-sm flex items-center justify-between">
      <div class="flex items-center gap-2">${icon("smart_toy", "text-secondary-fixed text-[20px]")}<span class="font-headline-md text-headline-md text-on-surface font-bold uppercase tracking-tight">AI Copilot</span></div>
      ${last ? aiBadge(last.mode) : html`<span class="font-label-sm text-label-sm text-outline">NOT RUN YET</span>`}
    </div>
    <div class="p-margin flex flex-col gap-space-sm">
      ${cached ? bubble("EXPLANATION (SAVED)", cached.text, cached.mode, 0) : ""}
      ${ai.thread.map((t) => bubble(t.q, t.text, t.mode, t.ms))}
      ${ai.loading ? html`<div class="bg-surface-container p-space-md"><div class="font-label-sm text-label-sm text-primary uppercase font-bold mb-1">// ${ai.label}</div><p id="ai-stream" class="font-body-md text-body-md text-on-surface leading-relaxed whitespace-pre-wrap">${ai.stream || "Thinking..."}</p></div>` : ""}
      ${ai.error ? html`<p class="font-body-md text-body-md text-error">${ai.error}</p>` : ""}
      ${!last && !ai.loading ? html`<p class="font-body-md text-body-md text-on-surface-variant">Ask the assistant to explain this alert in plain language. It only advises: it never changes anything by itself.</p>` : ""}
      <div class="flex flex-col gap-1.5">
        <span class="font-label-sm text-label-sm text-outline uppercase tracking-wider">GUIDED PROMPTS</span>
        <div class="flex items-center gap-space-xs overflow-x-auto no-scrollbar pb-1">
          ${QUICK_ACTIONS.map((q) => html`<button data-action="quick" data-id="${q.id}" ${ai.loading ? "disabled" : ""} class="flex-shrink-0 px-space-sm py-1 bg-surface-container-high hover:bg-primary-container text-on-surface hover:text-on-primary-container font-code-sm text-code-sm disabled:opacity-50">${q.label}</button>`)}
        </div>
      </div>
      <form data-form="ask" class="relative flex items-center bg-surface-container-highest">
        <span class="font-code-sm text-code-sm text-primary pl-space-sm font-bold select-none">gw-copilot://&gt;</span>
        <input name="q" data-input="chat" data-keep="chat" value="${chatText}" autocomplete="off" placeholder="Ask about this incident..." class="bg-transparent flex-grow px-space-sm py-2 font-code-sm text-code-sm text-on-surface placeholder-outline focus:outline-none min-w-0" />
        <button type="submit" ${ai.loading ? "disabled" : ""} aria-label="Send" class="px-space-md py-2 text-secondary-fixed disabled:opacity-50">${icon("send", "text-[19px]")}</button>
      </form>
      ${last ? html`<button data-action="copy" class="self-start flex items-center gap-1 text-primary hover:text-tertiary-fixed font-code-sm text-code-sm">${icon("content_copy", "text-[16px]")}<span>COPY LAST ANSWER</span></button>` : ""}
    </div>
  </div>`;
}

export function render() {
  const a = current();
  if (!a) {
    return !state.loaded.alerts ? skeleton(3)
      : html`<div class="flex flex-col gap-space-md"><a href="#/alerts" class="font-code-md text-code-md text-primary">← Back to alerts</a>${empty("Alert not found", "It may be older than the latest 500 alerts, or the link is wrong.", "search_off")}</div>`;
  }
  const s = SEV[a.severity] || SEV.low;
  const dev = deviceById(a.deviceId);
  const listed = watchByIp(a.srcIp);
  const realIp = isIp(a.srcIp);
  const isOpen = ["new", "acknowledged", "investigating"].includes(a.status);
  const evidence = Object.entries(a.evidence || {}).filter(([, v]) => v !== null && typeof v !== "object" || Array.isArray(v));
  const timeline = [...extras.timeline];
  const btn = "h-9 font-code-sm text-code-sm font-semibold uppercase tracking-wider flex items-center justify-center gap-1 transition-colors disabled:opacity-50";

  return html`
  <div class="flex flex-col gap-space-md">
    <div class="flex items-center justify-between bg-surface-container-lowest px-margin py-space-xs">
      <div class="flex items-center gap-space-xs font-label-sm text-label-sm tracking-wider"><a href="#/alerts" class="text-outline hover:text-on-surface">ALERTS</a><span class="text-outline-variant">/</span><span class="text-primary font-semibold">#${shortId(a.id)}</span></div>
      <span class="flex items-center gap-1.5 font-label-sm text-label-sm text-secondary-fixed tracking-widest font-semibold"><span class="w-1.5 h-1.5 bg-secondary-fixed rounded-full animate-ping"></span>LIVE</span>
    </div>
    <div class="${s.badge} px-margin py-space-sm flex items-center justify-between gap-2">
      <span class="font-label-md text-label-md uppercase tracking-wider font-bold truncate">${s.label} • ${(STATUS[a.status]?.label || a.status)}</span>
      <span class="px-space-xs py-0.5 bg-surface-container-lowest font-code-sm text-code-sm font-bold flex-shrink-0">seen ${a.count || 1}x</span>
    </div>

    <div class="grid gap-space-md lg:grid-cols-5">
      <div class="lg:col-span-3 flex flex-col gap-space-md">
        <div class="p-margin bg-surface-container-low flex flex-col gap-space-md">
          <div class="flex flex-col gap-1">
            <span class="font-label-sm text-label-sm text-outline uppercase tracking-wider font-semibold">// ${shortId(a.id)} • ${methodLabel(a.detectionMethod)} detection</span>
            <h1 class="font-headline-xl-mobile text-headline-xl-mobile text-on-surface font-bold tracking-tight">${typeLabel(a.type)}</h1>
            <p class="font-body-md text-body-md text-on-surface-variant">${a.description}</p>
          </div>
          <div class="grid grid-cols-1 sm:grid-cols-2 gap-space-sm">
            <div class="bg-surface-container p-space-md flex flex-col gap-1">
              <span class="font-label-sm text-label-sm text-outline uppercase flex items-center gap-1">${icon("dns", "text-[13px] text-tertiary")}Target</span>
              <div class="font-code-lg text-code-lg text-secondary font-semibold break-all">${dev ? dev.name : a.dstIp}</div>
              <div class="font-body-sm text-body-sm text-on-surface-variant"><span class="text-tertiary font-code-sm text-code-sm">${a.dstIp}</span>${a.dstPort ? html` • port ${a.dstPort} ${serviceName(a.dstPort)}` : ""}${a.protocol ? ` • ${a.protocol}` : ""}</div>
            </div>
            <div class="bg-surface-container p-space-md flex flex-col gap-1">
              <div class="flex items-center justify-between"><span class="font-label-sm text-label-sm text-outline uppercase flex items-center gap-1">${icon("satellite_alt", "text-[13px] text-error")}Source</span>
                ${typeof a.srcReputation === "number" ? html`<span class="px-1.5 py-0.5 bg-error text-on-error font-code-sm text-code-sm font-bold">SCORE ${a.srcReputation}/100</span>` : html`<span class="font-code-sm text-code-sm text-outline">NO REPUTATION SCORE YET</span>`}</div>
              <div class="font-code-lg text-code-lg ${s.text} font-semibold break-all">${srcLabel(a)}</div>
              <div class="font-body-sm text-body-sm text-on-surface-variant">${a.srcCountry ? `Country: ${a.srcCountry}` : "Country not looked up yet"}${listed ? (listed.blocked ? " • on the blocklist" : " • on the watchlist") : ""}</div>
            </div>
          </div>
          <div class="bg-surface-container p-space-md"><span class="font-label-sm text-label-sm text-outline uppercase tracking-wider">// WHY IT WAS FLAGGED</span><p class="font-body-md text-body-md text-on-surface mt-1">${a.reason}</p></div>
        </div>

        ${evidence.length ? html`
        <div class="p-margin flex flex-col gap-space-sm bg-surface">
          <span class="font-label-md text-label-md text-on-surface font-semibold tracking-wide flex items-center gap-1.5 uppercase">${icon("query_stats", "text-[16px] text-primary")}Evidence</span>
          <div class="grid grid-cols-2 gap-space-sm">${evidence.map(([k, v]) => html`<div class="bg-surface-container-high p-space-sm flex flex-col gap-1 min-w-0"><span class="font-label-sm text-label-sm text-outline truncate uppercase">${humanKey(k)}</span><span class="font-code-md text-code-md text-on-surface font-semibold break-words">${evidenceValue(v)}</span></div>`)}</div>
        </div>` : ""}

        ${(a.recommendedActions || []).length ? html`
        <div class="p-margin bg-surface-container-low flex flex-col gap-space-sm">
          <span class="font-label-md text-label-md text-on-surface font-semibold tracking-wide flex items-center gap-1.5 uppercase">${icon("checklist", "text-[16px] text-secondary-fixed")}Recommended next steps</span>
          <ol class="flex flex-col gap-1.5 list-decimal list-inside font-body-md text-body-md text-on-surface-variant">${a.recommendedActions.map((t) => html`<li>${t}</li>`)}</ol>
        </div>` : ""}

        <div class="p-margin bg-surface-container-low flex flex-col gap-space-md">
          <div class="flex items-center justify-between"><span class="font-label-md text-label-md text-on-surface font-semibold tracking-wide flex items-center gap-1.5 uppercase">${icon("history_toggle_off", "text-[16px] text-tertiary")}Timeline</span><span class="font-code-sm text-code-sm text-outline">${timeline.length} EVENTS</span></div>
          ${timeline.length ? html`<div class="flex flex-col gap-space-sm pl-2">${timeline.map((t, i) => html`
            <div class="flex gap-space-md"><div class="flex flex-col items-center"><div class="w-2.5 h-2.5 ${i === 0 ? "bg-primary-container" : "bg-outline"} rounded-full mt-1.5 flex-shrink-0"></div>${i < timeline.length - 1 ? html`<div class="w-0.5 bg-outline-variant h-full my-0.5"></div>` : ""}</div>
              <div class="bg-surface-container p-space-sm flex-grow flex flex-col gap-0.5 mb-1"><div class="flex items-center justify-between"><span class="font-code-sm text-code-sm text-secondary-fixed font-semibold">${fmtClock(t.at)}</span><span class="font-label-sm text-label-sm text-outline">${t.by || ""}</span></div>
              <span class="font-body-md text-body-md text-on-surface font-semibold">${t.title}</span>${t.detail ? html`<p class="font-body-sm text-body-sm text-on-surface-variant">${t.detail}</p>` : ""}</div></div>`)}</div>`
            : html`<p class="font-body-sm text-body-sm text-outline">Detected ${fmtDateTime(a.detectedAt)}. No other events yet.</p>`}
        </div>
      </div>

      <div class="lg:col-span-2 flex flex-col gap-space-md">
        <div class="p-margin bg-surface-container-low flex flex-col gap-space-sm">
          <span class="font-label-sm text-label-sm text-outline uppercase tracking-wider font-semibold">// RESPONSE</span>
          <div class="grid grid-cols-2 gap-space-sm">
            ${a.status === "new" ? html`<button data-action="status" data-status="acknowledged" ${busy ? "disabled" : ""} class="${btn} bg-secondary-fixed text-on-secondary-fixed col-span-2">${icon("check_circle", "text-[16px]")}ACKNOWLEDGE</button>` : ""}
            ${isOpen && a.status !== "investigating" ? html`<button data-action="status" data-status="investigating" ${busy ? "disabled" : ""} class="${btn} bg-surface-container-high text-secondary-fixed">${icon("manage_search", "text-[16px]")}INVESTIGATING</button>` : ""}
            ${isOpen ? html`<button data-action="status" data-status="resolved" ${busy ? "disabled" : ""} class="${btn} bg-primary-container text-on-primary-container">${icon("check_circle", "text-[16px]")}RESOLVE</button>
              <button data-action="status" data-status="false_positive" ${busy ? "disabled" : ""} class="${btn} bg-surface-container-high text-outline hover:text-on-surface col-span-2">${icon("close", "text-[16px]")}MARK FALSE POSITIVE</button>`
              : html`<button data-action="status" data-status="new" ${busy ? "disabled" : ""} class="${btn} bg-surface-container-high text-on-surface col-span-2">${icon("restart_alt", "text-[16px]")}REOPEN</button>`}
            ${realIp ? (listed && listed.blocked
              ? html`<button data-action="unblock" ${busy ? "disabled" : ""} class="${btn} bg-surface-container text-outline hover:text-on-surface col-span-2">${icon("shield", "text-[16px]")}REMOVE ${a.srcIp} FROM BLOCKLIST</button>`
              : html`<button data-action="block" ${busy ? "disabled" : ""} class="${btn} bg-error-container text-on-error-container col-span-2">${icon("shield", "text-[16px]")}BLOCKLIST ${a.srcIp}</button>`) : ""}
          </div>
          <p class="font-body-sm text-body-sm text-outline">${realIp ? "GateWatch keeps the blocklist. Your firewall or network team enforces it." : "This alert has many (probably spoofed) sources, so there is no single IP to blocklist."}</p>
        </div>

        ${aiPanel(a)}

        <div class="p-margin bg-surface-container-low flex flex-col gap-space-sm">
          <span class="font-label-md text-label-md text-on-surface font-semibold tracking-wide flex items-center gap-1.5 uppercase">${icon("note_alt", "text-[16px] text-outline")}Analyst notes</span>
          <form data-form="note" class="flex flex-col gap-space-xs">
            <textarea name="text" data-input="note" data-keep="note" rows="3" maxlength="2000" placeholder="// Findings, ticket numbers, who you told..." class="w-full bg-surface-container-highest text-on-surface p-space-sm font-code-sm text-code-sm focus:outline-none placeholder-outline resize-none">${noteText}</textarea>
            <button type="submit" class="self-end px-3 py-1.5 bg-surface-container-high text-secondary-fixed font-label-sm text-label-sm uppercase font-bold">Add note</button>
          </form>
          ${extras.notes.length ? html`<div class="flex flex-col gap-space-xs">${extras.notes.map((n) => html`<div class="bg-surface-container p-space-sm"><div class="flex justify-between font-label-sm text-label-sm text-outline"><span>${n.authorName}</span><span>${timeAgo(n.createdAt)}</span></div><p class="font-body-md text-body-md text-on-surface whitespace-pre-wrap mt-0.5">${n.text}</p></div>`)}</div>`
            : html`<p class="font-body-sm text-body-sm text-outline">No notes yet. Notes can't be edited or deleted once added.</p>`}
        </div>
      </div>
    </div>
  </div>`;
}

async function runAi(label, fn, alert, save) {
  if (ai.loading) return;
  ai.loading = true; ai.label = label; ai.stream = ""; ai.error = "";
  const t0 = performance.now();
  bus.render();
  try {
    const r = await fn({
      onToken: (_p, full) => {
        ai.stream = full;
        const el = document.getElementById("ai-stream");
        if (el) el.textContent = full;
      },
    });
    ai.thread.push({ q: label, text: r.text, mode: r.mode, ms: Math.round(performance.now() - t0) });
    if (save) saveAiSummary(alert.id, { text: r.text, mode: r.mode }).catch(() => {});
  } catch (e) {
    ai.error = friendlyError(e);
  }
  ai.loading = false;
  ai.stream = "";
  bus.render();
}

async function act(fn, okMessage) {
  busy = true;
  bus.render();
  try {
    await fn();
    toast(okMessage, "ok");
  } catch (e) {
    toast(explainError(e), "error");
  }
  busy = false;
  bus.render();
}

export const handlers = {
  status(el) { const a = current(); if (a) act(() => setAlertStatus(a, el.dataset.status), `Marked ${STATUS[el.dataset.status].label.toLowerCase()}`); },
  block() { const a = current(); if (a) act(() => blockIp(a.srcIp, { reason: a.description, alertId: a.id }), `${a.srcIp} added to the blocklist`); },
  unblock() { const a = current(); if (a) act(() => unblockIp(a.srcIp, a.id), `${a.srcIp} removed from the blocklist`); },
  quick(el) {
    const a = current();
    const q = QUICK_ACTIONS.find((x) => x.id === el.dataset.id);
    if (a && q) runAi(q.label, (o) => runQuickAction(q.id, a, o), a, q.id === "explain");
  },
  copy() {
    const last = ai.thread[ai.thread.length - 1] || current()?.aiSummary;
    if (last && navigator.clipboard) navigator.clipboard.writeText(last.text).then(() => toast("Copied", "ok"));
  },
};
export const inputs = {
  note: (v) => { noteText = v; },
  chat: (v) => { chatText = v; },
};
export const forms = {
  ask(data) {
    const a = current();
    const question = String(data.get("q") || "").trim();
    if (!a || !question) return;
    chatText = "";
    runAi(question, (o) => askAboutAlert(a, question, o), a, false);
  },
  note(data) {
    const text = String(data.get("text") || "").trim();
    if (!text) return;
    noteText = "";
    act(() => addNote(alertId, text), "Note added");
  },
};