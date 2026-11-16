import "./styles/main.css";
import { loadConfig } from "./firebase.js";
import { getOnDeviceStatus } from "./ai.js";
import { onChange, onNewAlert, state } from "./store.js";
import { watchAuth } from "./auth.js";
import { bus, getNotifPrefs, SEV, SEV_RANK, srcLabel, toast, toStr, typeLabel } from "./ui.js";
import { bellIsOpen, closeBell, errorsHtml, headerHtml, navHtml, setAiStatus, shellHandlers, shellHtml } from "./layout.js";
import * as login from "./pages/login.js";
import * as pending from "./pages/pending.js";
import * as dashboard from "./pages/dashboard.js";
import * as incident from "./pages/incident.js";
import * as logs from "./pages/logs.js";
import * as intel from "./pages/intel.js";
import * as reports from "./pages/reports.js";
import * as settings from "./pages/settings.js";
import * as more from "./pages/more.js";
import { alertsPage, incidentsPage } from "./pages/alerts.js";

const PAGES = { dashboard, alerts: alertsPage, incidents: incidentsPage, alert: incident, logs, intel, reports, settings, more };

const $ = (id) => document.getElementById(id);
let mode = null;     // loading | login | pending | app
let view = null;     // the page currently on screen
let routeKey = null;

function parseRoute() {
  const [name = "dashboard", ...params] = location.hash.replace(/^#\/?/, "").split("/");
  return { name: PAGES[name] ? name : "dashboard", params };
}

function leave() {
  if (view && view.unmount) view.unmount();
  view = null;
  routeKey = null;
}

function setMode(next, v) {
  if (mode === next) return false;
  if (mode === "app") leave();
  mode = next;
  view = v || null;
  return true;
}

function render() {
  const app = $("app");
  const s = state.authStatus;

  if (s === "loading") {
    setMode("loading");
    app.innerHTML = `<div class="min-h-screen flex items-center justify-center font-label-sm text-label-sm text-secondary-fixed tracking-widest animate-pulse">// GATEWATCH :: STARTING</div>`;
    return;
  }
  if (s === "signedOut" || s === "pending") {
    const page = s === "signedOut" ? login : pending;
    setMode(s === "signedOut" ? "login" : "pending", page);
    view = page;
    app.innerHTML = toStr(page.render());
    return;
  }

  if (setMode("app")) app.innerHTML = toStr(shellHtml());
  const route = parseRoute();
  const key = `${route.name}/${route.params.join("/")}`;
  if (key !== routeKey) {
    if (view && view.unmount) view.unmount();
    routeKey = key;
    view = PAGES[route.name];
    if (view.mount) view.mount(route.params);
    window.scrollTo(0, 0);
  }

  $("hdr").innerHTML = toStr(headerHtml());
  $("nav").innerHTML = toStr(navHtml(route.name));
  $("errors").innerHTML = toStr(errorsHtml());

  // re-render the page but keep the cursor in whatever box the user is typing in
  const root = $("page-inner");
  const a = document.activeElement;
  const keep = a && root.contains(a) && a.dataset && a.dataset.keep
    ? { key: a.dataset.keep, s: a.selectionStart, e: a.selectionEnd } : null;
  root.innerHTML = toStr(view.render(route.params));
  if (keep) {
    const n = root.querySelector(`[data-keep="${keep.key}"]`);
    if (n) { n.focus(); try { n.setSelectionRange(keep.s, keep.e); } catch { /* not a text box */ } }
  }
}

// live data can arrive many times a second: draw at most every 400ms
let timer = null;
let lastDraw = 0;
function scheduleRender() {
  if (timer) return;
  timer = setTimeout(() => { timer = null; lastDraw = Date.now(); render(); }, Math.max(0, 400 - (Date.now() - lastDraw)));
}
bus.render = () => { lastDraw = Date.now(); render(); };

// ------------------------------------------------------------- user input
const find = (e, attr) => e.target.closest && e.target.closest(`[data-${attr}]`);
const table = (kind) => (view && view[kind]) || {};

document.addEventListener("click", (e) => {
  if (bellIsOpen() && !(e.target.closest && e.target.closest("#bell-wrap"))) { closeBell(); render(); }
  const el = find(e, "action");
  if (!el) return;
  const fn = table("handlers")[el.dataset.action] || shellHandlers[el.dataset.action];
  if (fn) { fn(el, e); render(); }
});
document.addEventListener("input", (e) => {
  const el = find(e, "input");
  const fn = el && table("inputs")[el.dataset.input];
  if (fn && fn(el.value, el, e) === true) render();
});
document.addEventListener("change", (e) => {
  const el = find(e, "change");
  const fn = el && table("changes")[el.dataset.change];
  if (fn) { fn(el.value, el, e); render(); }
});
document.addEventListener("submit", (e) => {
  const el = find(e, "form");
  if (!el) return;
  e.preventDefault();
  const fn = table("forms")[el.dataset.form];
  if (fn) { fn(new FormData(el), el, e); render(); }
});
window.addEventListener("hashchange", () => { closeBell(); render(); });

// ----------------------------------------------------------------- startup
async function refreshAi() {
  setAiStatus(await getOnDeviceStatus());
  if (mode === "app") render();
}
window.addEventListener("gw-ai-status", refreshAi);

// pop a toast when a new alert arrives (respects Settings > Notifications)
onNewAlert((a) => {
  const prefs = getNotifPrefs();
  if (!prefs.inApp || (SEV_RANK[a.severity] ?? 0) < (SEV_RANK[prefs.minSeverity] ?? 0)) return;
  toast(`${(SEV[a.severity] || SEV.low).label}: ${typeLabel(a.type)} from ${srcLabel(a)}`, a.severity === "critical" || a.severity === "high" ? "error" : "info");
});

onChange(scheduleRender);
setInterval(() => { if (mode === "app") scheduleRender(); }, 30000); // keep "2m ago" fresh
render();
loadConfig();
watchAuth();
refreshAi();