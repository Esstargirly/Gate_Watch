import { addDoc, serverTimestamp, setDoc, updateDoc } from "firebase/firestore";
import { state, wcol, wdoc } from "./store.js";
import { STATUS, ipDocId } from "./ui.js";

const me = () => state.profile;
const myName = () => me()?.displayName || me()?.email || "you";

export function explainError(err) {
  const code = err?.code || "";
  if (code.includes("permission-denied")) return "That isn't allowed.";
  if (code.includes("unavailable")) return "Can't reach Firebase right now.";
  return err?.message || "That didn't work.";
}

// who did what (shown in Settings > Audit). Never blocks the main action.
export async function audit(action, targetType, targetId, details = {}) {
  try {
    await addDoc(wcol("auditLog"), {
      actorUid: me().uid, actorEmail: me().email, action, targetType, targetId, details,
      timestamp: serverTimestamp(),
    });
  } catch (e) {
    console.warn("audit failed", e);
  }
}

export async function addTimeline(alertId, title, detail = "") {
  try {
    await addDoc(wcol("alerts", alertId, "timeline"), { at: serverTimestamp(), title, detail, by: myName() });
  } catch (e) {
    console.warn("timeline failed", e);
  }
}

export async function setAlertStatus(alert, status) {
  const patch = { status };
  if (status === "acknowledged") Object.assign(patch, { acknowledgedBy: me().uid, acknowledgedAt: serverTimestamp() });
  if (status === "resolved" || status === "false_positive") Object.assign(patch, { resolvedBy: me().uid, resolvedAt: serverTimestamp() });
  await updateDoc(wdoc("alerts", alert.id), patch);
  addTimeline(alert.id, `Marked ${STATUS[status].label.toLowerCase()}`, `By ${myName()}`);
  audit("alert.status", "alert", alert.id, { from: alert.status, to: status });
}

export async function addNote(alertId, text) {
  await addDoc(wcol("alerts", alertId, "notes"), {
    authorUid: me().uid, authorName: myName(), text: text.trim(), createdAt: serverTimestamp(),
  });
  audit("alert.note", "alert", alertId);
}

// "Blocklist" = GateWatch keeps the list. Your firewall/team does the blocking.
export async function blockIp(ip, { reason = "", alertId = null } = {}) {
  const existing = state.watchlist.find((w) => w.ip === ip);
  if (existing) {
    await updateDoc(wdoc("watchlist", existing.id), { blocked: true });
  } else {
    await setDoc(wdoc("watchlist", ipDocId(ip)), {
      ip, addedAt: serverTimestamp(), reason, hits: 0, blocked: true, addedBy: me().uid,
    });
  }
  if (alertId) addTimeline(alertId, `${ip} added to the blocklist`, `By ${myName()}`);
  audit("ip.block", "ip", ip, { alertId });
}

export async function unblockIp(ip, alertId = null) {
  const existing = state.watchlist.find((w) => w.ip === ip);
  if (!existing) return;
  await updateDoc(wdoc("watchlist", existing.id), { blocked: false });
  if (alertId) addTimeline(alertId, `${ip} removed from the blocklist`, `By ${myName()}`);
  audit("ip.unblock", "ip", ip, { alertId });
}

export async function addWatchIp(ip, reason, blocked) {
  if (state.watchlist.some((w) => w.ip === ip)) throw new Error("That IP is already on the watchlist.");
  await setDoc(wdoc("watchlist", ipDocId(ip)), {
    ip, addedAt: serverTimestamp(), reason: reason || "", hits: 0, blocked: !!blocked, addedBy: me().uid,
  });
  audit("ip.add", "ip", ip, { blocked: !!blocked });
}

export async function markDeviceKnown(device) {
  await updateDoc(wdoc("devices", device.id), { known: true });
  audit("device.known", "device", device.id, { name: device.name });
}