import { authMessage, resetPassword, signIn, signUp } from "../auth.js";
import { LOGO, bus, html, icon } from "../ui.js";

let mode = "signin"; // signin | signup
let email = "", password = "", name = "";
let showPw = false, busy = false, error = "", info = "";

export function render() {
  const signup = mode === "signup";
  return html`
  <div class="relative min-h-screen flex flex-col items-center justify-center px-margin py-8 overflow-hidden">
    <div class="absolute inset-0 tech-grid opacity-40 pointer-events-none"></div>
    <div class="relative w-full max-w-sm flex flex-col gap-space-lg">
      <div class="flex flex-col items-center text-center">
        <div class="relative p-2 mb-space-sm bg-surface-container-lowest shadow-md">
          <img alt="GateWatch" class="w-14 h-14 object-contain" src="${LOGO}" />
          <div class="absolute -top-1 -right-1 w-2 h-2 bg-secondary-fixed"></div>
          <div class="absolute -bottom-1 -left-1 w-2 h-2 bg-primary-container"></div>
        </div>
        <div class="flex items-center gap-1">
          <span class="font-code-lg text-code-lg text-primary-container tracking-wider">//</span>
          <h1 class="font-headline-xl-mobile text-headline-xl-mobile tracking-wider uppercase text-secondary font-bold">GateWatch</h1>
        </div>
        <p class="font-label-sm text-label-sm text-outline tracking-widest uppercase mt-0.5">Always watching. Always protecting.</p>
      </div>

      <form data-form="auth" class="bg-surface-container-lowest p-margin flex flex-col gap-space-md shadow-md" novalidate>
        <div class="font-label-sm text-label-sm text-tertiary">// ${signup ? "REQUEST_ACCESS" : "OPERATOR_SIGN_IN"}</div>
        ${signup ? html`
        <label class="flex flex-col gap-1">
          <span class="font-label-sm text-label-sm text-on-surface-variant uppercase tracking-wider">Your name</span>
          <input data-input="name" data-keep="name" value="${name}" autocomplete="name" class="bg-surface-container-low px-space-md py-space-sm font-code-md text-code-md text-secondary focus:outline-none focus:bg-surface-container" />
        </label>` : ""}
        <label class="flex flex-col gap-1">
          <span class="font-label-sm text-label-sm text-on-surface-variant uppercase tracking-wider">Email</span>
          <span class="flex items-center bg-surface-container-low px-space-md py-space-sm">
            <span class="font-code-sm text-code-sm text-primary-container select-none mr-2 font-bold">gw-id://</span>
            <input data-input="email" data-keep="email" value="${email}" type="email" autocomplete="email" spellcheck="false" class="w-full bg-transparent font-code-md text-code-md text-secondary focus:outline-none" />
          </span>
        </label>
        <label class="flex flex-col gap-1">
          <span class="flex justify-between items-center">
            <span class="font-label-sm text-label-sm text-on-surface-variant uppercase tracking-wider">Password</span>
            ${signup ? "" : html`<button type="button" data-action="forgot" class="font-label-sm text-label-sm text-primary active:opacity-70">FORGOT?</button>`}
          </span>
          <span class="flex items-center bg-surface-container-low px-space-md py-space-sm">
            <input data-input="password" data-keep="password" value="${password}" type="${showPw ? "text" : "password"}" autocomplete="${signup ? "new-password" : "current-password"}" class="w-full bg-transparent font-code-md text-code-md text-secondary focus:outline-none" />
            <button type="button" data-action="togglePw" aria-label="Show or hide password" class="text-outline hover:text-secondary flex items-center p-0.5">${icon(showPw ? "visibility_off" : "visibility", "text-base")}</button>
          </span>
        </label>
        ${error ? html`<div class="bg-error-container text-on-error-container px-space-md py-space-sm font-code-sm text-code-sm">${error}</div>` : ""}
        ${info ? html`<div class="bg-surface-container-high text-secondary-fixed px-space-md py-space-sm font-code-sm text-code-sm">${info}</div>` : ""}
        <button type="submit" ${busy ? "disabled" : ""} class="w-full bg-secondary-container text-on-secondary-container font-code-lg text-code-lg font-bold py-space-md flex items-center justify-center gap-2 tracking-widest uppercase transition-all active:scale-[0.99] disabled:opacity-60">
          <span>${busy ? "WORKING..." : signup ? "REQUEST ACCESS" : "AUTHENTICATE"}</span>${icon("arrow_forward", "text-base")}
        </button>
        <button type="button" data-action="setMode" data-mode="${signup ? "signin" : "signup"}" class="font-code-md text-code-md text-primary hover:text-secondary uppercase tracking-wide py-1">
          ${signup ? "Already approved? Sign in" : "New here? Request access"}
        </button>
      </form>

      <p class="text-center font-label-sm text-label-sm text-outline uppercase tracking-wider flex items-center justify-center gap-1.5">
        ${icon("lock", "text-xs text-primary")} Encrypted connection (TLS) • An admin approves new accounts
      </p>
    </div>
  </div>`;
}

export const inputs = {
  name: (v) => { name = v; },
  email: (v) => { email = v; },
  password: (v) => { password = v; },
};

export const handlers = {
  togglePw() { showPw = !showPw; },
  setMode(el) { mode = el.dataset.mode; error = ""; info = ""; },
  async forgot() {
    error = ""; info = "";
    if (!email.trim()) { error = "Type your email first, then tap FORGOT?"; return; }
    try {
      await resetPassword(email.trim());
      info = "If that email has an account, a reset link is on its way.";
    } catch (e) {
      error = authMessage(e);
    }
    bus.render();
  },
};

export const forms = {
  async auth() {
    error = ""; info = "";
    if (!email.trim() || !password) { error = "Enter your email and password."; return; }
    if (mode === "signup" && !name.trim()) { error = "Enter your name so an admin knows who you are."; return; }
    busy = true;
    try {
      if (mode === "signup") await signUp(name.trim(), email.trim(), password);
      else await signIn(email.trim(), password);
      password = "";
    } catch (e) {
      error = authMessage(e);
    }
    busy = false;
    bus.render();
  },
};