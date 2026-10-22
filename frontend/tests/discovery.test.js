import { describe, expect, it } from "vitest";

import { discover, tunnelFromAnswer, validName } from "../src/discovery.js";

const answer = (data) => ({ Answer: [{ data }] });

describe("what DNS may tell the page", () => {
  it("accepts a quoted or split TXT record holding a tunnel address", () => {
    expect(tunnelFromAnswer(answer('"https://a-b-c.trycloudflare.com"'))).toBe("https://a-b-c.trycloudflare.com");
    expect(tunnelFromAnswer(answer('"https://a-b-c.try" "cloudflare.com"'))).toBe("https://a-b-c.trycloudflare.com");
  });

  it.each([
    ["another host", '"https://evil.example.com"'],
    ["plain http", '"http://a.trycloudflare.com"'],
    ["a suffix trick", '"https://a.trycloudflare.com.evil.com"'],
    ["a path", '"https://x.trycloudflare.com/path"'],
    ["a port", '"https://x.trycloudflare.com:8443"'],
    ["credentials", '"https://user@x.trycloudflare.com"']
  ])("refuses %s", (_, data) => {
    expect(tunnelFromAnswer(answer(data))).toBe("");
  });

  it("copes with an empty answer", () => {
    expect(tunnelFromAnswer({})).toBe("");
    expect(tunnelFromAnswer(null)).toBe("");
  });
});

describe("server names", () => {
  it("normalises and validates", () => {
    expect(validName("MyIds.DuckDNS.org")).toBe("myids.duckdns.org");
    expect(validName("a b")).toBe("");
    expect(validName("localhost")).toBe("");
    expect(validName("")).toBe("");
  });
});

describe("looking the address up", () => {
  const good = async () => ({ ok: true, json: async () => answer('"https://q-w-e.trycloudflare.com"') });

  it("returns the tunnel address", async () => {
    expect(await discover("myids.duckdns.org", good)).toBe("https://q-w-e.trycloudflare.com");
  });

  it("falls back to the second resolver when the first fails", async () => {
    let calls = 0;

    const flaky = async (...args) => {
      calls += 1;

      if (calls === 1) throw new Error("down");

      return good(...args);
    };

    expect(await discover("myids.duckdns.org", flaky)).toBe("https://q-w-e.trycloudflare.com");
    expect(calls).toBe(2);
  });

  it("does not even ask about a bad name", async () => {
    let asked = false;

    expect(await discover("bad name", async () => { asked = true; return good(); })).toBe("");
    expect(asked).toBe(false);
  });
});
