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

async function failure(response) {
  if (response.status === 401) unauthorized();

  let detail = `${response.status}`;

  try {
    detail = (await response.json()).detail || detail;
  } catch {
    /* not JSON */
  }

  return new Error(detail);
}

export async function getJSON(url) {
  const response = await fetch(apiUrl(url), { headers: authHeaders() });

  if (!response.ok) throw await failure(response);

  return response.json();
}

export async function send(url, method, body) {
  const response = await fetch(apiUrl(url), {
    method,
    headers: authHeaders({ "Content-Type": "application/json" }),
    body: body === undefined ? undefined : JSON.stringify(body)
  });

  if (!response.ok) throw await failure(response);

  return response.json();
}

export { unauthorized };
