/**
 * Where the backend lives. Empty (the default) means the same origin that served
 * this page, which is how `serve.py` and the reverse proxy work. When the page is on
 * a static host such as Netlify, build with VITE_API_URL=https://ids.example.com.
 */
const configured = (import.meta.env.VITE_API_URL || "").trim().replace(/\/+$/, "");

export const API_BASE = configured;

export const apiUrl = (path) => `${API_BASE}${path}`;

/** The websocket address for a path such as "/ws?token=...". */
export function wsUrl(path) {
  const origin = API_BASE || location.origin;

  return `${origin.replace(/^http/, "ws")}${path}`;
}
