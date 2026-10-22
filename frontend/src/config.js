/**
 * Where the backend lives. Empty means the origin that served this page, which is how
 * `serve.py` and a reverse proxy work. When the pages are on a static host such as
 * Netlify the backend is somewhere else; its address is, in order of preference:
 *   1. the one the person confirmed on the "Connect" screen (kept in this browser),
 *   2. VITE_API_URL given at build time.
 */
const KEY = "ids_api";

const clean = (value) => (value || "").trim().replace(/\/+$/, "");

/** https://host[:port] only (http for this machine); anything else is not a backend. */
export function validBackend(value) {
  try {
    const url = new URL(clean(value));

    const local = ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname);

    if (url.protocol !== "https:" && !(url.protocol === "http:" && local)) return "";

    if (url.username || url.password || url.pathname !== "/" || url.search || url.hash) return "";

    return url.origin;
  } catch {
    return "";
  }
}

export function getApiBase() {
  try {
    const stored = validBackend(localStorage.getItem(KEY));

    if (stored) return stored;
  } catch {
    /* storage unavailable */
  }

  return validBackend(import.meta.env.VITE_API_URL) || "";
}

export function setApiBase(value) {
  try {
    if (value) localStorage.setItem(KEY, value);
    else localStorage.removeItem(KEY);
  } catch {
    /* storage unavailable: the choice lasts until reload */
  }
}

const NAME_KEY = "ids_name";

/** The DuckDNS name that publishes the server's current address (see discovery.js). */
export function getDiscoveryName() {
  try {
    const stored = localStorage.getItem(NAME_KEY);

    if (stored) return stored;
  } catch {
    /* storage unavailable */
  }

  return (import.meta.env.VITE_DISCOVERY_NAME || "").trim().toLowerCase();
}

export function setDiscoveryName(value) {
  try {
    if (value) localStorage.setItem(NAME_KEY, value);
    else localStorage.removeItem(NAME_KEY);
  } catch {
    /* storage unavailable */
  }
}

/** The name a link offers (?name=...), not yet trusted. */
export function offeredName() {
  return (new URLSearchParams(location.search).get("name") || "").trim().toLowerCase();
}

/** A backend address offered by a link (?api=...), not yet trusted. */
export function offeredBackend() {
  return validBackend(new URLSearchParams(location.search).get("api"));
}

export const apiUrl = (path) => `${getApiBase()}${path}`;

/** The websocket address for a path such as "/ws?ticket=...". */
export function wsUrl(path) {
  const origin = getApiBase() || location.origin;

  return `${origin.replace(/^http/, "ws")}${path}`;
}
