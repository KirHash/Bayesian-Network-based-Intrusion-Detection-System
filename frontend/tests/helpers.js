import { vi } from "vitest";

export { wsUrl } from "../src/config.js";

/**
 * A fake server: routes are "METHOD /path" keys mapping to a JSON body, a [status, body] pair or a
 * function of the request. Returns the fetch mock and the list of calls it received.
 */
export function api(routes) {
  const calls = [];

  const fetchMock = vi.fn(async (url, options = {}) => {
    const path = String(url).replace(/^https?:\/\/[^/]+/, "").split("?")[0];
    const method = (options.method || "GET").toUpperCase();
    const body = options.body ? JSON.parse(options.body) : undefined;

    calls.push({ method, path, body, headers: options.headers || {} });

    // a route can name its host ("GET https://x.trycloudflare.com/api/auth"); that wins over the bare path
    const route = routes[`${method} ${String(url).split("?")[0]}`] ?? routes[`${method} ${path}`];

    if (route === undefined) {
      return { ok: false, status: 404, headers: new Headers(), json: async () => ({ detail: "not found" }) };
    }

    const answer = typeof route === "function" ? route({ method, path, body }) : route;

    const [status, payload, headers] = Array.isArray(answer) && typeof answer[0] === "number" ? answer : [200, answer];

    return {
      ok: status < 400,
      status,
      headers: new Headers(headers || {}),
      json: async () => payload
    };
  });

  vi.stubGlobal("fetch", fetchMock);

  return { calls, fetchMock };
}

/** A location the test can inspect: reload() is recorded instead of leaving the page. */
export function fakeLocation(extra = {}) {
  const reload = vi.fn();

  vi.stubGlobal("location", {
    origin: "http://localhost:3000",
    protocol: "http:",
    host: "localhost:3000",
    pathname: "/",
    search: "",
    hash: "",
    reload,
    ...extra
  });

  return { reload };
}
