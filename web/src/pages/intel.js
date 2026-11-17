
import { addWatchIp, blockIp, explainError, markDeviceKnown, unblockIp } from "../actions.js";
import { state } from "../store.js";
import { bus, empty, fmtNum, html, icon, isIp, skeleton, timeAgo, toast } from "../ui.js";

let tab = "watchlist";
let q = "";
let adding = false;
let form = { ip: "", reason: "", blocked: true };

export function mount(params) {
  tab = params[0] === "devices" ? "devices" : "watchlist";
}

const repColor = (n) => (n >= 80 ? ["text-error", "bg-error"] : n >= 60 ? ["text-[#ff7a00]", "bg-[#e65100]"] : n >= 40 ? ["text-[#f1c40f]", "bg-[#fbc02d]"] : ["text-on-surface-variant", "bg-outline"]);

function watchlistView() {
  const needle = q.trim().toLowerCase();
  const all = [...state.watchlist].sort((a, b) => (b.blocked - a.blocked) || ((b.lastSeen?.getTime() || 0) - (a.lastSeen?.getTime() || 0)));
  const rows = all.filter((w) => !needle || [w.ip, w.country, w.reason].join(" ").toLowerCase().includes(needle));
  const blocked = all.filter((w) => w.blocked).length;
  const hits = all.reduce((n, w) => n + (w.hits || 0), 0);
  return html`
  <div class="flex flex-col gap-space-md">
    <div class="flex flex-col gap-space-xs bg-surface-container-lowest p-space-sm">
      <div class="relative flex items-center">
        <span class="absolute left-2.5 font-code-sm text-code-sm text-primary-container font-bold pointer-events-none">gw-filter://&gt;</span>
        <input data-input="q" data-keep="q" value="${q}" placeholder="Search IP, country or reason..." class="w-full bg-surface-container-low text-on-surface font-code-sm text-code-sm pl-28 pr-8 py-2 placeholder-outline outline-none focus:bg-surface-container-high" />
      </div>
      <div class="flex justify-end pt-1"><button data-action="toggleAdd" class="flex items-center gap-1 px-2.5 py-1.5 bg-secondary-fixed text-on-secondary-fixed font-label-sm text-label-sm font-bold uppercase active:scale-95 transition-transform">${icon(adding ? "close" : "add", "text-[14px]")}<span>${adding ? "Cancel" : "Add IP to watchlist"}</span></button></div>
      ${adding ? html`
      <form data-form="addip" class="flex flex-col gap-space-xs bg-surface-container-low p-space-sm" novalidate>
        <input name="ip" data-input="fip" data-keep="fip" value="${form.ip}" placeholder="IP address, e.g. 203.0.113.9" class="bg-surface-container-highest px-2 py-1.5 font-code-md text-code-md text-secondary focus:outline-none" />
        <input name="reason" data-input="freason" data-keep="freason" value="${form.reason}" placeholder="Why? (optional)" maxlength="200" class="bg-surface-container-highest px-2 py-1.5 font-code-md text-code-md text-secondary focus:outline-none" />
        <label class="flex items-center gap-2 font-code-sm text-code-sm text-on-surface-variant"><input type="checkbox" name="blocked" data-change="fblocked" ${form.blocked ? "checked" : ""} /> Also put it on the blocklist</label>
        <button type="submit" class="self-end px-3 py-1.5 bg-surface-container-high text-secondary-fixed font-label-sm text-label-sm uppercase font-bold">Save</button>
      </form>` : ""}
    </div>
    <div class="grid grid-cols-3 gap-space-xs">
      <div class="bg-surface-container-low p-2"><div class="font-label-sm text-label-sm text-outline uppercase">Blocklisted</div><div class="font-code-lg text-code-lg font-bold text-error">${blocked} / ${all.length}</div></div>
      <div class="bg-surface-container-low p-2"><div class="font-label-sm text-label-sm text-outline uppercase">Total hits</div><div class="font-code-lg text-code-lg font-bold text-on-surface">${fmtNum(hits)}</div></div>
      <div class="bg-surface-container-low p-2"><div class="font-label-sm text-label-sm text-outline uppercase">Scored IPs</div><div class="font-code-lg text-code-lg font-bold text-secondary-fixed">${all.filter((w) => typeof w.reputationScore === "number").length}</div></div>
    </div>
    ${!state.loaded.watchlist ? skeleton(3) : rows.length ? html`<div class="grid gap-space-xs md:grid-cols-2">${rows.map((w) => {
      const score = typeof w.reputationScore === "number" ? w.reputationScore : null;
      const [txt, bar] = score == null ? ["text-outline", "bg-outline"] : repColor(score);
      return html`<div class="relative bg-surface-container-low p-space-sm hover:bg-surface-container">
        <div class="absolute left-0 top-0 bottom-0 w-1 ${w.blocked ? "bg-error" : "bg-outline-variant"}"></div>
        <div class="flex items-start justify-between gap-space-xs pl-2">
          <div class="flex flex-col min-w-0">
            <div class="flex items-center gap-space-xs flex-wrap"><span class="font-code-lg text-code-lg font-bold text-on-surface tracking-tight">${w.ip}</span>${w.country ? html`<span class="px-1.5 bg-surface-container-highest font-code-sm text-code-sm text-on-surface-variant font-bold">${w.country}</span>` : ""}</div>
            <div class="flex items-center gap-space-md mt-1 font-code-sm text-code-sm text-on-surface-variant"><span>Seen: <strong class="text-on-surface">${w.hits || 0}x</strong></span><span>Last: <strong class="text-secondary-fixed">${timeAgo(w.lastSeen)}</strong></span></div>
            ${w.reason ? html`<div class="mt-1 font-body-sm text-body-sm text-outline truncate" title="${w.reason}">${w.reason}</div>` : ""}
          </div>
          <label class="flex flex-col items-end flex-shrink-0 cursor-pointer gap-1">
            <span class="flex items-center gap-1.5"><span class="font-label-sm text-label-sm uppercase text-outline">BLOCKLISTED</span>
              <button data-action="toggleBlock" data-ip="${w.ip}" data-blocked="${w.blocked ? "1" : "0"}" role="switch" aria-checked="${w.blocked ? "true" : "false"}" class="w-8 h-4 ${w.blocked ? "bg-secondary-fixed" : "bg-surface-container-highest"} relative flex items-center px-0.5"><span class="w-3 h-3 ${w.blocked ? "bg-on-secondary-fixed translate-x-4" : "bg-outline translate-x-0"} shadow transform transition-transform"></span></button></span>
          </label>
        </div>
        <div class="mt-2.5 pl-2 flex flex-col gap-1">
          <div class="flex justify-between items-center font-label-sm text-label-sm"><span class="text-outline uppercase">Reputation threat score</span><span class="font-code-sm text-code-sm font-bold ${txt}">${score == null ? "NO SCORE YET" : `${score} / 100`}</span></div>
          <div class="w-full h-1.5 bg-surface-container-highest overflow-hidden"><div class="h-full ${bar}" style="width:${score ?? 0}%"></div></div>
        </div>
      </div>`;
    })}</div>` : empty("Nothing on the watchlist", needle ? "No IPs match that search." : "Attacking IPs are added here automatically when the sensor sees them.", "verified_user")}
    <p class="font-body-sm text-body-sm text-outline">Blocklisted means GateWatch marks the IP for your firewall or team to act on. It does not block traffic by itself.</p>
  </div>`;
}

function devicesView() {
  const list = [...state.devices].sort((a, b) => (a.known - b.known) || ((b.lastSeen?.getTime() || 0) - (a.lastSeen?.getTime() || 0)));
  const unknown = list.filter((d) => !d.known).length;
  return html`
  <div class="flex flex-col gap-space-md">
    <div class="flex items-center justify-between bg-surface-container-lowest p-space-sm">
      <div class="flex items-center gap-space-sm"><div class="w-2 h-2 ${unknown ? "bg-error-container animate-pulse" : "bg-secondary-fixed"}"></div>
        <div class="flex flex-col"><span class="font-label-sm text-label-sm text-on-surface uppercase font-bold">${unknown ? `${unknown} UNKNOWN DEVICE${unknown > 1 ? "S" : ""} DETECTED` : "ALL DEVICES KNOWN"}</span><span class="font-code-sm text-code-sm text-outline">${list.length} seen • ${list.filter((d) => d.status === "online").length} online</span></div></div>
    </div>
    ${!state.loaded.devices ? skeleton(3) : list.length ? html`<div class="grid gap-space-xs md:grid-cols-2">${list.map((d) => html`
      <div class="relative bg-surface-container-low p-space-sm ${d.status === "offline" ? "opacity-80 hover:opacity-100" : ""}">
        <div class="absolute left-0 top-0 bottom-0 w-1 ${!d.known ? "bg-error" : d.status === "online" ? "bg-secondary-fixed" : "bg-outline-variant"}"></div>
        <div class="flex flex-col gap-space-xs pl-2">
          <div class="flex items-start justify-between gap-space-xs">
            <div class="flex flex-col min-w-0"><div class="flex items-center gap-1.5"><span class="w-2 h-2 ${!d.known ? "bg-error animate-ping" : d.status === "online" ? "bg-secondary-fixed" : "bg-outline"}"></span><span class="font-headline-md text-headline-md font-bold text-on-surface truncate">${d.name}</span></div>
              <div class="flex items-center gap-space-sm mt-0.5 font-code-sm text-code-sm flex-wrap"><span class="text-primary font-bold">${d.ip}</span><span class="text-outline">MAC: ${d.mac}</span></div></div>
            <span class="px-2 py-0.5 ${!d.known ? "bg-error-container text-on-error-container" : d.status === "online" ? "bg-surface-container-high text-secondary-fixed" : "bg-surface-container text-outline"} font-label-sm text-label-sm font-bold uppercase flex-shrink-0">${!d.known ? "UNKNOWN" : d.status === "online" ? "ONLINE" : "OFFLINE"}</span>
          </div>
          <div class="flex items-center justify-between pt-1 font-code-sm text-code-sm bg-surface-container-lowest px-2 py-1.5"><span class="text-outline truncate">${d.lastActivity ? `Recent: ${d.lastActivity}` : "First seen " + timeAgo(d.firstSeen)}</span><span class="text-on-surface-variant flex-shrink-0 ml-2">${timeAgo(d.lastSeen)}</span></div>
          ${!d.known ? html`<div class="pt-1 flex items-center justify-end gap-space-xs"><span class="font-body-sm text-body-sm text-outline">Not confirmed by an analyst</span><button data-action="known" data-id="${d.id}" class="px-3 py-1.5 bg-surface-container-highest hover:bg-surface-bright text-secondary-fixed font-label-sm text-label-sm font-bold uppercase active:scale-95">[ MARK AS KNOWN ]</button></div>` : ""}
        </div>
      </div>`)}</div>` : empty("No devices yet", "Devices appear when the sensor sees them on the local network.", "devices")}
  </div>`;
}

export function render() {
  const tabBtn = (key, ic, label, count) => html`<button data-action="tab" data-tab="${key}" class="relative flex items-center justify-center gap-1.5 py-2.5 px-space-xs ${tab === key ? "bg-surface-container-high text-on-surface" : "bg-surface-container-low text-on-surface-variant"}">
    ${icon(ic, `text-[16px] ${tab === key ? "text-secondary-fixed" : "text-outline"}`)}<span class="font-label-md text-label-md font-bold uppercase tracking-tight">${label} (${count})</span><div class="absolute bottom-0 left-0 right-0 h-0.5 ${tab === key ? "bg-secondary-fixed" : "bg-transparent"}"></div></button>`;
  return html`
  <div class="flex flex-col gap-space-md">
    <div class="flex items-center gap-space-xs py-space-sm"><span class="w-1.5 h-1.5 bg-primary-container"></span><span class="font-label-sm text-label-sm text-on-surface-variant uppercase tracking-wider">// GW-SOC :: INTEL &amp; NETWORK_DEVICES</span></div>
    <div class="grid grid-cols-2 gap-space-xs">${tabBtn("watchlist", "shield", "Watchlist", state.watchlist.length)}${tabBtn("devices", "devices", "Devices", state.devices.length)}</div>
    ${tab === "watchlist" ? watchlistView() : devicesView()}
  </div>`;
}

async function run(fn, ok) {
  let good = true;
  try { await fn(); toast(ok, "ok"); } catch (e) { good = false; toast(explainError(e), "error"); }
  bus.render();
  return good;
}

export const inputs = {
  q: (v) => { q = v; return true; },
  fip: (v) => { form.ip = v; },
  freason: (v) => { form.reason = v; },
};
export const changes = { fblocked(_v, el) { form.blocked = el.checked; } };
export const handlers = {
  tab(el) { tab = el.dataset.tab; },
  toggleAdd() { adding = !adding; },
  toggleBlock(el) {
    const ip = el.dataset.ip;
    el.dataset.blocked === "1" ? run(() => unblockIp(ip), `${ip} removed from the blocklist`) : run(() => blockIp(ip), `${ip} added to the blocklist`);
  },
  known(el) {
    const d = state.devices.find((x) => x.id === el.dataset.id);
    if (d) run(() => markDeviceKnown(d), `${d.name} marked as known`);
  },
};
export const forms = {
  addip(data) {
    const ip = String(data.get("ip") || "").trim();
    if (!isIp(ip)) { toast("That doesn't look like an IP address.", "error"); return; }
    const reason = String(data.get("reason") || "").trim();
    const blocked = !!data.get("blocked");
    run(() => addWatchIp(ip, reason, blocked), `${ip} added`).then((good) => {
      if (!good) return;
      form = { ip: "", reason: "", blocked: true };
      adding = false;
      bus.render();
    });
  },
};