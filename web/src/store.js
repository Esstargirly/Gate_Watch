import { collection, doc, limit, onSnapshot, orderBy, query } from "firebase/firestore";
import { db } from "./firebase.js";

export const state = {
  authStatus: "loading", // loading | signedOut | pending | ready
  user: null,
  profile: null,
  authError: null,
  alerts: [],
  traffic: [],
  devices: [],
  watchlist: [],
  sensors: [],
  statsToday: null,
  users: [],
  audit: [],
  loaded: {},
  errors: {},
};

const changeListeners = new Set();
const newAlertListeners = new Set();
export const onChange = (fn) => { changeListeners.add(fn); return () => changeListeners.delete(fn); };
export const onNewAlert = (fn) => { newAlertListeners.add(fn); return () => newAlertListeners.delete(fn); };
export const notify = () => changeListeners.forEach((fn) => fn());

// Firestore Timestamps -> Dates, plus the document id
export function fromDoc(snap) {
  const out = { id: snap.id };
  for (const [k, v] of Object.entries(snap.data() || {})) out[k] = v && typeof v.toDate === "function" ? v.toDate() : v;
  if (out.aiSummary && out.aiSummary.generatedAt && out.aiSummary.generatedAt.toDate) {
    out.aiSummary = { ...out.aiSummary, generatedAt: out.aiSummary.generatedAt.toDate() };
  }
  return out;
}

const todayId = () => new Date().toISOString().slice(0, 10); // UTC, same as schema.py
let unsubs = [];

export function stopData() {
  unsubs.forEach((u) => u());
  unsubs = [];
  Object.assign(state, { alerts: [], traffic: [], devices: [], watchlist: [], sensors: [], statsToday: null, users: [], audit: [], loaded: {}, errors: {} });
}

function listen(key, ref, { many = true, onAdded } = {}) {
  let first = true;
  unsubs.push(
    onSnapshot(
      ref,
      (snap) => {
        if (many) {
          state[key] = snap.docs.map(fromDoc);
          if (!first && onAdded) snap.docChanges().forEach((c) => c.type === "added" && onAdded(fromDoc(c.doc)));
        } else {
          state[key] = snap.exists() ? fromDoc(snap) : null;
        }
        first = false;
        state.loaded[key] = true;
        delete state.errors[key];
        notify();
      },
      (err) => {
        console.error(`[GateWatch] ${key} listener failed`, err);
        state.errors[key] = err;
        state.loaded[key] = true;
        notify();
      }
    )
  );
}

export function startData(role) {
  stopData();
  listen("alerts", query(collection(db, "alerts"), orderBy("detectedAt", "desc"), limit(500)), {
    onAdded: (a) => {
      // only announce genuinely new alerts, not old ones sliding into the window
      if (a.detectedAt && Date.now() - a.detectedAt.getTime() < 300000) newAlertListeners.forEach((fn) => fn(a));
    },
  });
  listen("traffic", query(collection(db, "traffic"), orderBy("ts", "desc"), limit(200)));
  listen("devices", collection(db, "devices"));
  listen("watchlist", collection(db, "watchlist"));
  listen("sensors", collection(db, "sensors"));
  listen("statsToday", doc(db, "stats", todayId()), { many: false });
  if (role === "admin") {
    listen("users", collection(db, "users"));
    listen("audit", query(collection(db, "auditLog"), orderBy("timestamp", "desc"), limit(100)));
  }
}

// timeline + notes for one alert (used by the incident page)
export function watchAlertExtras(alertId, cb) {
  const t = onSnapshot(
    query(collection(db, "alerts", alertId, "timeline"), orderBy("at")),
    (s) => cb("timeline", s.docs.map(fromDoc)),
    (e) => console.error("timeline", e)
  );
  const n = onSnapshot(
    query(collection(db, "alerts", alertId, "notes"), orderBy("createdAt", "desc")),
    (s) => cb("notes", s.docs.map(fromDoc)),
    (e) => console.error("notes", e)
  );
  return () => { t(); n(); };
}

// ------------------------------------------------------------------ selectors
export const isStaff = (p) => !!p && (p.role === "admin" || p.role === "analyst");
export const isAdmin = () => state.profile?.role === "admin";
export const openAlerts = () => state.alerts.filter((a) => ["new", "acknowledged", "investigating"].includes(a.status));
export const deviceById = (id) => state.devices.find((d) => d.id === id);
export const watchByIp = (ip) => state.watchlist.find((w) => w.ip === ip);
export function latestSensor() {
  return [...state.sensors].sort((a, b) => (b.lastHeartbeat?.getTime() || 0) - (a.lastHeartbeat?.getTime() || 0))[0] || null;
}
export const sensorOnline = () => {
  const s = latestSensor();
  return !!(s && s.lastHeartbeat && Date.now() - s.lastHeartbeat.getTime() < 120000);
};