import { initializeApp } from "firebase/app";
import { initializeAppCheck, ReCaptchaV3Provider } from "firebase/app-check";
import { getAuth } from "firebase/auth";
import { getFirestore } from "firebase/firestore";
import {
  getRemoteConfig,
  fetchAndActivate,
  getValue,
} from "firebase/remote-config";

const firebaseConfig = {
  apiKey: import.meta.env.VITE_FIREBASE_API_KEY,
  authDomain: import.meta.env.VITE_FIREBASE_AUTH_DOMAIN,
  projectId: import.meta.env.VITE_FIREBASE_PROJECT_ID,
  storageBucket: import.meta.env.VITE_FIREBASE_STORAGE_BUCKET,
  messagingSenderId: import.meta.env.VITE_FIREBASE_MESSAGING_SENDER_ID,
  appId: import.meta.env.VITE_FIREBASE_APP_ID,
};

export const app = initializeApp(firebaseConfig);
if (import.meta.env.DEV) {
  self.FIREBASE_APPCHECK_DEBUG_TOKEN =
    import.meta.env.VITE_APPCHECK_DEBUG_TOKEN || true;
} else if (!import.meta.env.VITE_RECAPTCHA_SITE_KEY) {
  console.warn(
    "[GateWatch] VITE_RECAPTCHA_SITE_KEY is missing. App Check will fail and " +
      "AI Logic requests will be rejected."
  );
}

export const appCheck = initializeAppCheck(app, {
  provider: new ReCaptchaV3Provider(
    import.meta.env.VITE_RECAPTCHA_SITE_KEY || "missing-site-key"
  ),
  isTokenAutoRefreshEnabled: true,
});

// ----------------------------------------------------------- Auth + Firestore
export const auth = getAuth(app);
export const db = getFirestore(app);

export const CONFIG_DEFAULTS = {
  port_scan_ports: 20,
  port_scan_window_sec: 10,
  brute_force_attempts: 5,
  brute_force_window_sec: 60,
  syn_flood_packets_per_sec: 100,
  traffic_spike_multiplier: 3.0,
  alert_dedup_window_sec: 300,
  traffic_retention_hours: 24,
  prefer_on_device_ai: true,
};

export const remoteConfig = getRemoteConfig(app);
remoteConfig.defaultConfig = CONFIG_DEFAULTS;
// short interval while developing so changes show up fast, 1 hour in production
remoteConfig.settings.minimumFetchIntervalMillis = import.meta.env.DEV
  ? 10_000
  : 3_600_000;

// Current values as a plain object, typed to match the defaults.
export function currentConfig() {
  const out = {};
  for (const [key, def] of Object.entries(CONFIG_DEFAULTS)) {
    const value = getValue(remoteConfig, key);
    if (typeof def === "boolean") out[key] = value.asBoolean();
    else if (typeof def === "number") out[key] = value.asNumber();
    else out[key] = value.asString();
  }
  return out;
}

// Call once when the app starts. Never throws: on failure you get the defaults.
export async function loadConfig() {
  try {
    await fetchAndActivate(remoteConfig);
  } catch (err) {
    console.warn("[GateWatch] Remote Config fetch failed, using defaults.", err);
  }
  return currentConfig();
}