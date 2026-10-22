import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";

import IpInfo from "../src/components/IpInfo.jsx";
import { ipKind, lookupLinks } from "../src/ipinfo.js";
import { api } from "./helpers.js";

describe("what kind of address", () => {
  it.each([
    ["10.1.2.3", "private"],
    ["192.168.0.9", "private"],
    ["172.16.0.1", "private"],
    ["172.31.255.255", "private"],
    ["172.32.0.1", "public"],
    ["100.64.0.1", "private"],
    ["127.0.0.1", "loopback"],
    ["169.254.10.1", "link-local"],
    ["239.255.255.250", "multicast"],
    ["224.0.0.251", "multicast"],
    ["0.0.0.0", "reserved"],
    ["255.255.255.255", "reserved"],
    ["8.8.8.8", "public"],
    ["::1", "loopback"],
    ["fe80::1", "link-local"],
    ["fd12:3456::1", "private"],
    ["ff02::fb", "multicast"],
    ["2606:4700:4700::1111", "public"]
  ])("%s is %s", (address, kind) => {
    expect(ipKind(address)).toBe(kind);
  });

  it.each(["", "not an address", "1.2.3", "1.2.3.4.5", "999.1.1.1", "1.2.3.-4", null, undefined])(
    "says nothing about %s",
    (value) => {
      expect(ipKind(value)).toBeNull();
    }
  );

  it("builds lookup links that cannot be bent into something else", () => {
    const links = lookupLinks("8.8.8.8");

    expect(links.map(([site]) => site)).toEqual(["AbuseIPDB", "VirusTotal", "Shodan"]);
    expect(links.every(([, url]) => url.startsWith("https://") && url.includes("8.8.8.8"))).toBe(true);

    expect(lookupLinks("1.1.1.1/../../x")[0][1]).not.toContain("/../");
  });
});

describe("one address in an alert", () => {
  it("explains a private address and offers no lookup", () => {
    api({});

    render(<IpInfo address="192.168.10.50" label="to" />);

    expect(screen.getByText("private")).toBeTruthy();
    expect(screen.getByText("inside a private network")).toBeTruthy();
    expect(screen.queryByText("look up its name")).toBeNull();
    expect(document.querySelector("a")).toBeNull();
  });

  it("looks a public address up only when asked", async () => {
    const { calls } = api({ "GET /api/lookup/8.8.8.8": { address: "8.8.8.8", kind: "public", name: "dns.google" } });

    render(<IpInfo address="8.8.8.8" label="from" />);

    // nothing leaves the page until the person asks
    expect(calls).toHaveLength(0);

    await userEvent.click(screen.getByText("look up its name"));

    expect(await screen.findByText("dns.google")).toBeTruthy();
    expect(calls).toHaveLength(1);
  });

  it("says when no name is registered", async () => {
    api({ "GET /api/lookup/8.8.4.4": { address: "8.8.4.4", kind: "public", name: null } });

    render(<IpInfo address="8.8.4.4" label="from" />);

    await userEvent.click(screen.getByText("look up its name"));

    expect(await screen.findByText("no name registered")).toBeTruthy();
  });

  it("copes with the lookup failing", async () => {
    api({ "GET /api/lookup/8.8.4.4": [500, { detail: "broken" }] });

    render(<IpInfo address="8.8.4.4" label="from" />);

    await userEvent.click(screen.getByText("look up its name"));

    expect(await screen.findByText("no name registered")).toBeTruthy();
  });

  it("opens outside sites in a new tab without handing over the page", () => {
    api({});

    render(<IpInfo address="8.8.8.8" label="from" />);

    const links = [...document.querySelectorAll("a")];

    expect(links).toHaveLength(3);

    for (const link of links) {
      expect(link.target).toBe("_blank");
      expect(link.rel).toContain("noopener");
      expect(link.rel).toContain("noreferrer");
    }
  });

  it("shows nothing for something that is not an address", () => {
    api({});

    const { container } = render(<IpInfo address="" label="from" />);

    expect(container.textContent).toBe("");
  });
});
