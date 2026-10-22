import { describe, expect, it, vi } from "vitest";

import { getJSON, getToken, send, setToken } from "../src/api.js";
import { api } from "./helpers.js";

describe("talking to the server", () => {
  it("sends the signed-in person's token", async () => {
    const { calls } = api({ "GET /api/stats": { total: 3 } });

    setToken("secret-token");

    expect(await getJSON("/api/stats")).toEqual({ total: 3 });
    expect(calls[0].headers.Authorization).toBe("Bearer secret-token");
  });

  it("sends nothing when nobody is signed in", async () => {
    const { calls } = api({ "GET /api/stats": {} });

    await getJSON("/api/stats");

    expect(calls[0].headers.Authorization).toBeUndefined();
  });

  it("posts JSON", async () => {
    const { calls } = api({ "POST /api/replay": { ok: true } });

    await send("/api/replay", "POST", { running: true });

    expect(calls[0]).toMatchObject({ method: "POST", body: { running: true } });
    expect(calls[0].headers["Content-Type"]).toBe("application/json");
  });

  it("raises the server's own explanation", async () => {
    api({ "PATCH /api/account": [400, { detail: "that username is taken" }] });

    await expect(send("/api/account", "PATCH", {})).rejects.toThrow("that username is taken");
  });

  it("tells the page when the server asks for a two-factor code", async () => {
    api({ "PATCH /api/account": [400, { detail: "enter the code", two_factor: true }] });

    const error = await send("/api/account", "PATCH", {}).catch((e) => e);

    expect(error.twoFactor).toBe(true);
  });

  it("sends the person back to the sign-in page on a 401", async () => {
    api({ "GET /api/stats": [401, { detail: "sign in required" }] });

    const heard = vi.fn();

    window.addEventListener("ids-unauthorized", heard);

    await expect(getJSON("/api/stats")).rejects.toThrow("sign in required");

    window.removeEventListener("ids-unauthorized", heard);

    expect(heard).toHaveBeenCalledOnce();
  });

  it("keeps the token in this browser only, and survives storage being unavailable", () => {
    setToken("abc");

    expect(getToken()).toBe("abc");

    setToken("");

    expect(getToken()).toBe("");

    vi.spyOn(Storage.prototype, "getItem").mockImplementation(() => {
      throw new Error("blocked");
    });

    expect(getToken()).toBe("");
  });
});
