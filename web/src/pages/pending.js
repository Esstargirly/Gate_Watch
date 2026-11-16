import { logout } from "../auth.js";
import { LOGO, html, icon } from "../ui.js";
import { state } from "../store.js";

export function render() {
  const err = state.authError;
  return html`
  <div class="relative min-h-screen flex items-center justify-center px-margin py-8 overflow-hidden">
    <div class="absolute inset-0 tech-grid opacity-40 pointer-events-none"></div>
    <div class="relative w-full max-w-sm bg-surface-container-lowest p-margin flex flex-col gap-space-md shadow-md text-center items-center">
      <img alt="GateWatch" class="w-12 h-12 object-contain" src="${LOGO}" />
      <div class="font-label-sm text-label-sm text-secondary-fixed tracking-widest uppercase">// AWAITING_APPROVAL</div>
      <h1 class="font-headline-md text-headline-md text-on-surface">Your account is waiting for an admin</h1>
      <p class="font-body-md text-body-md text-on-surface-variant">
        You're signed in as <span class="font-code-md text-code-md text-primary">${state.user?.email || ""}</span>.
        An administrator needs to give you the Analyst or Admin role. This page updates by itself when they do.
      </p>
      ${err ? html`<p class="font-code-sm text-code-sm text-error break-words">${err.code || ""} ${err.message || ""}</p>` : ""}
      <button data-action="signout" class="w-full bg-surface-container text-error font-code-md text-code-md py-space-sm flex items-center justify-center gap-1.5 uppercase active:bg-surface-container-high">
        ${icon("logout", "text-sm")}<span class="tracking-wide">Sign out</span>
      </button>
    </div>
  </div>`;
}

export const handlers = {
  signout() { logout(); },
};