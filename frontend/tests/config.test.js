import { describe, expect, it } from "vitest";

import {
  apiUrl,
  getApiBase,
  getDiscoveryName,
  offeredBackend,
  setApiBase,
  setDiscoveryName,
  validBackend,
  wsUrl
} from "../src/config.js";

describe("which backend addresses are acceptable", () => {
  it.each([
    ["https://x.trycloudflare.com", "https://x.trycloudflare.com"],
    ["https://x.trycloudflare.com/", "https://x.trycloudflare.com"],
    ["http://localhost:8000", "http://localhost:8000"],
    ["http://127.0.0.1:8000", "http://127.0.0.1:8000"]
  ])("keeps %s", (input, expected) => {
    expect(validBackend(input)).toBe(expected);
  });

  it.each([
    "http://example.com",
    "javascript:alert(1)",
    "https://user:pass@x.com",
    "https://x.com/path",
    "https://x.com/?q=1",
    "ftp://x.com",
    "not a url",
    ""
  ])("refuses %s", (input) => {
    expect(validBackend(input)).toBe("");
  });
});

describe("remembering the server", () => {
  it("uses the same origin until told otherwise", () => {
    expect(getApiBase()).toBe("");
    expect(apiUrl("/api/auth")).toBe("/api/auth");
  });

  it("prefers the address the person confirmed", () => {
    setApiBase("https://one.trycloudflare.com");

    expect(getApiBase()).toBe("https://one.trycloudflare.com");
    expect(apiUrl("/api/auth")).toBe("https://one.trycloudflare.com/api/auth");

    setApiBase("");

    expect(getApiBase()).toBe("");
  });

  it("ignores a stored value that is not a valid address", () => {
    localStorage.setItem("ids_api", "javascript:alert(1)");

    expect(getApiBase()).toBe("");
  });

  it("remembers the DuckDNS name", () => {
    expect(getDiscoveryName()).toBe("");

    setDiscoveryName("myids.duckdns.org");

    expect(getDiscoveryName()).toBe("myids.duckdns.org");
  });

  it("turns the address into a websocket address", () => {
    setApiBase("https://one.trycloudflare.com");

    expect(wsUrl("/ws?ticket=t")).toBe("wss://one.trycloudflare.com/ws?ticket=t");
  });
});

describe("an address offered by a link is only an offer", () => {
  it("is read from ?api= and validated", () => {
    history.replaceState(null, "", "/?api=https://x.trycloudflare.com");

    expect(offeredBackend()).toBe("https://x.trycloudflare.com");

    history.replaceState(null, "", "/?api=http://evil.example.com");

    expect(offeredBackend()).toBe("");

    // and reading it stores nothing
    expect(getApiBase()).toBe("");
  });
});
