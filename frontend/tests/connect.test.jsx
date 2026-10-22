import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";

import ConnectGate from "../src/components/ConnectGate.jsx";
import { api, fakeLocation } from "./helpers.js";

const WORKING = { required: true, ok: true, user: "alice", role: "admin", signup: "closed" };

function mount() {
  return render(
    <ConnectGate>
      <div>the sign-in page</div>
    </ConnectGate>
  );
}

describe("finding the server", () => {
  it("passes straight through when the server on this origin answers", async () => {
    api({ "GET /api/auth": WORKING });

    mount();

    expect(await screen.findByText("the sign-in page")).toBeTruthy();
  });

  it("asks for the server's DuckDNS name once, when it knows nothing", async () => {
    api({});

    mount();

    await userEvent.type(await screen.findByPlaceholderText("myids.duckdns.org"), "MyIds.duckdns.org");
    await userEvent.click(screen.getByRole("button", { name: "CONNECT" }));

    expect(localStorage.getItem("ids_name")).toBe("myids.duckdns.org");
  });

  it("refuses something that is not a server name or address", async () => {
    api({});

    mount();

    await userEvent.type(await screen.findByPlaceholderText("myids.duckdns.org"), "not a name");
    await userEvent.click(screen.getByRole("button", { name: "CONNECT" }));

    expect(await screen.findByText(/Enter the server's DuckDNS name/)).toBeTruthy();
    expect(localStorage.getItem("ids_name")).toBeNull();
  });

  it("finds a new tunnel address by itself when the remembered one is dead", async () => {
    localStorage.setItem("ids_name", "myids.duckdns.org");
    localStorage.setItem("ids_api", "https://dead-dead-dead.trycloudflare.com");

    api({
      "GET https://dead-dead-dead.trycloudflare.com/api/auth": () => {
        throw new TypeError("network error");
      },
      "GET https://dns.google/resolve": { Answer: [{ data: '"https://fresh-new-one.trycloudflare.com"' }] },
      "GET https://fresh-new-one.trycloudflare.com/api/auth": WORKING
    });

    mount();

    expect(await screen.findByText("the sign-in page")).toBeTruthy();
    expect(localStorage.getItem("ids_api")).toBe("https://fresh-new-one.trycloudflare.com");
  });

  it("keeps the sign-in token when only the address changed (it is the same server)", async () => {
    localStorage.setItem("ids_name", "myids.duckdns.org");
    localStorage.setItem("ids_api", "https://dead.trycloudflare.com");
    localStorage.setItem("ids_token", "still-valid");

    api({
      "GET https://dead.trycloudflare.com/api/auth": () => {
        throw new TypeError("network error");
      },
      "GET https://dns.google/resolve": { Answer: [{ data: "https://alive.trycloudflare.com" }] },
      "GET https://alive.trycloudflare.com/api/auth": WORKING
    });

    mount();

    await screen.findByText("the sign-in page");

    expect(localStorage.getItem("ids_token")).toBe("still-valid");
  });

  it("never follows DNS to a site that is not a tunnel", async () => {
    localStorage.setItem("ids_name", "myids.duckdns.org");
    localStorage.setItem("ids_api", "https://dead.trycloudflare.com");

    api({
      "GET https://dead.trycloudflare.com/api/auth": () => {
        throw new TypeError("network error");
      },
      "GET https://dns.google/resolve": { Answer: [{ data: '"https://evil.example.com"' }] },
      "GET https://cloudflare-dns.com/dns-query": { Answer: [{ data: '"https://evil.example.com"' }] }
    });

    mount();

    // the person sees the sign-in form to type into, and the address did not move
    expect(await screen.findByPlaceholderText("Username")).toBeTruthy();
    expect(localStorage.getItem("ids_api")).toBe("https://dead.trycloudflare.com");
  });

  it("signs in for the person as soon as the server answers", async () => {
    localStorage.setItem("ids_name", "myids.duckdns.org");
    localStorage.setItem("ids_api", "https://later.trycloudflare.com");

    // signing in reloads the page, which jsdom cannot do
    fakeLocation();

    let up = false;

    const { calls } = api({
      "GET https://later.trycloudflare.com/api/auth": () => {
        if (!up) throw new TypeError("not yet");

        return WORKING;
      },
      "GET https://dns.google/resolve": { Answer: [] },
      "GET https://cloudflare-dns.com/dns-query": { Answer: [] },
      "POST https://later.trycloudflare.com/api/login": { token: "T", username: "alice", role: "admin" }
    });

    mount();

    // typed while the server is still starting
    await userEvent.type(await screen.findByPlaceholderText("Username"), "alice");
    await userEvent.type(screen.getByPlaceholderText("Password"), "correct horse battery");
    await userEvent.click(document.querySelector(".auth-go"));

    expect(await screen.findByText(/Signing in as soon as your server answers/)).toBeTruthy();

    up = true;

    await waitFor(() => expect(calls.some((c) => c.path === "/api/login")).toBe(true), { timeout: 8000 });
  }, 15000);
});

describe("a link that carries an address", () => {
  it("asks before trusting it", async () => {
    history.replaceState(null, "", "/?api=https://offered.trycloudflare.com&name=myids.duckdns.org");

    // agreeing reloads the page, which jsdom cannot do
    fakeLocation({ search: "?api=https://offered.trycloudflare.com&name=myids.duckdns.org" });

    api({});

    mount();

    expect(await screen.findByText("CONNECT?")).toBeTruthy();
    expect(screen.getByText("https://offered.trycloudflare.com")).toBeTruthy();

    // nothing is stored until the person agrees
    expect(localStorage.getItem("ids_api")).toBeNull();

    await userEvent.click(screen.getByRole("button", { name: "CONNECT" }));

    expect(localStorage.getItem("ids_api")).toBe("https://offered.trycloudflare.com");
    expect(localStorage.getItem("ids_name")).toBe("myids.duckdns.org");
  });

  it("can be declined", async () => {
    history.replaceState(null, "", "/?api=https://offered.trycloudflare.com");

    // declining reloads the page, which jsdom cannot do
    fakeLocation({ search: "?api=https://offered.trycloudflare.com" });

    api({ "GET /api/auth": WORKING });

    mount();

    await userEvent.click(await screen.findByRole("button", { name: "Cancel" }));

    expect(localStorage.getItem("ids_api")).toBeNull();
    expect(await screen.findByText("the sign-in page")).toBeTruthy();
  });

  it("ignores an address that is not https", async () => {
    history.replaceState(null, "", "/?api=http://evil.example.com");

    api({ "GET /api/auth": WORKING });

    mount();

    expect(await screen.findByText("the sign-in page")).toBeTruthy();
    expect(screen.queryByText("CONNECT?")).toBeNull();
  });
});
