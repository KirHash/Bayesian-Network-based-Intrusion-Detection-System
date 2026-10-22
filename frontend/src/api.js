import { apiUrl } from "./config.js";

const KEY = "ids_token";

export function getToken() {
  try {
    return localStorage.getItem(KEY) || "";
  } catch {
    return "";
  }
}

export function setToken(token) {
  try {
    if (token) localStorage.setItem(KEY, token);
    else localStorage.removeItem(KEY);
  } catch {
    /* storage unavailable: the token lasts until reload */
  }
}

const authHeaders = (extra = {}) => {
  const token = getToken();
  return token ? { ...extra, Authorization: `Bearer ${token}` } : extra;
};

/** Tell the login gate that the server wants a (new) admin token. */
function unauthorized() {
  window.dispatchEvent(new Event("ids-unauthorized"));
}

/** fetch, but a dead network or an unreachable server becomes a sentence a person can act on. */
async function reach(url, options) {
  try {
    return await fetch(apiUrl(url), options);
  } catch {
    throw new Error("Cannot reach the server. Check your connection, or that the server is running.");
  }
}

async function failure(response) {
  if (response.status === 401) unauthorized();

  let detail =
    response.status === 429
      ? "Too many requests. Wait a moment and try again."
      : response.status >= 500
      ? "The server had a problem. Try again in a moment."
      : `${response.status}`;
  let body = {};

  try {
    body = await response.json();
    detail = body.detail || detail;
  } catch {
    /* not JSON */
  }

  const error = new Error(detail);

  // the server asks for an authenticator code
  error.twoFactor = body.two_factor === true;

  return error;
}

export async function getJSON(url) {
  const response = await reach(url, { headers: authHeaders() });

  if (!response.ok) throw await failure(response);

  return response.json();
}

export async function send(url, method, body) {
  const response = await reach(url, {
    method,
    headers: authHeaders({ "Content-Type": "application/json" }),
    body: body === undefined ? undefined : JSON.stringify(body)
  });

  if (!response.ok) throw await failure(response);

  return response.json();
}

/** Send a file's bytes as they are (a backup to restore from). */
export async function upload(url, file) {
  const response = await reach(url, {
    method: "POST",
    headers: authHeaders({ "Content-Type": "application/octet-stream" }),
    body: file
  });

  if (!response.ok) throw await failure(response);

  return response.json();
}

/** Save a server answer as a file. A plain link cannot send the token, so the file is fetched here. */
export async function download(url, fallbackName = "download") {
  const response = await reach(url, { headers: authHeaders() });

  if (!response.ok) throw await failure(response);

  const name =
    /filename="([^"]+)"/.exec(response.headers.get("Content-Disposition") || "")?.[1] || fallbackName;

  const link = document.createElement("a");

  link.href = URL.createObjectURL(await response.blob());
  link.download = name;

  document.body.appendChild(link);
  link.click();
  link.remove();

  URL.revokeObjectURL(link.href);
}

export { unauthorized };
