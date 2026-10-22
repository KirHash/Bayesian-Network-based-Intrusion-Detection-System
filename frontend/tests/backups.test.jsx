import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import { getJSON } from "../src/api.js";
import BackupsPanel from "../src/components/BackupsPanel.jsx";
import CrashScreen from "../src/components/CrashScreen.jsx";
import LoginGate from "../src/components/LoginGate.jsx";
import { api, fakeLocation } from "./helpers.js";

afterEach(() => vi.useRealTimers());

const ROW = {
  name: "ids-auto-20261022-020000.db",
  kind: "auto",
  label: "Automatic",
  size: 52_000,
  created: "2026-10-22 02:00:00"
};

const LISTING = { backups: [ROW], keep: 7, folder: "D:\\ids\\backups", last_error: "", due: false };

describe("backups and recovery", () => {
  it("lists the copies with where they are kept and how many stay", async () => {
    api({ "GET /api/backups": LISTING });

    render(<BackupsPanel />);

    expect(await screen.findByText("2026-10-22 02:00:00")).toBeTruthy();
    expect(screen.getByText("Automatic")).toBeTruthy();
    expect(screen.getByText(/newest 7 are kept/)).toBeTruthy();
    expect(screen.getByText("D:\\ids\\backups")).toBeTruthy();
  });

  it("makes a copy now and shows the list again", async () => {
    let made = false;

    const { calls } = api({
      "GET /api/backups": () => (made ? { ...LISTING, backups: [{ ...ROW, name: "ids-manual-x.db", kind: "manual", label: "Manual" }, ROW] } : LISTING),
      "POST /api/backups": () => {
        made = true;

        return { name: "ids-manual-x.db", size: 2048 };
      }
    });

    render(<BackupsPanel />);

    await userEvent.click(await screen.findByRole("button", { name: "Back up now" }));

    expect(await screen.findByText(/Saved ids-manual-x.db/)).toBeTruthy();
    expect(await screen.findByText("Manual")).toBeTruthy();
    expect(calls.some((c) => c.method === "POST" && c.path === "/api/backups")).toBe(true);
  });

  it("asks before replacing everything, and nothing happens if you cancel", async () => {
    const { calls } = api({ "GET /api/backups": LISTING });

    render(<BackupsPanel />);

    await userEvent.click(await screen.findByRole("button", { name: "Restore" }));

    expect(screen.getByText(/replaces all alerts, accounts and settings/)).toBeTruthy();

    await userEvent.click(screen.getByRole("button", { name: "Cancel" }));

    expect(screen.queryByText(/replaces all alerts/)).toBeNull();
    expect(calls.some((c) => c.path.endsWith("/restore"))).toBe(false);
  });

  it("restores after the confirmation and says what was kept", async () => {
    fakeLocation();

    const { calls } = api({
      "GET /api/backups": LISTING,
      [`POST /api/backups/${ROW.name}/restore`]: {
        restored: ROW.name,
        safety: "ids-before-restore-20261022-030000.db",
        alerts: 1200,
        users: 3
      }
    });

    render(<BackupsPanel />);

    await userEvent.click(await screen.findByRole("button", { name: "Restore" }));
    await userEvent.click(screen.getByRole("button", { name: "Yes, replace everything" }));

    expect(await screen.findByText(/1,200 alerts and 3 accounts/)).toBeTruthy();
    expect(screen.getByText(/ids-before-restore-20261022-030000.db/)).toBeTruthy();
    expect(calls.filter((c) => c.path.endsWith("/restore"))).toHaveLength(1);
  });

  it("shows the server's reason when a restore or upload is refused", async () => {
    api({
      "GET /api/backups": LISTING,
      [`POST /api/backups/${ROW.name}/restore`]: [400, { detail: "that file is damaged (the database integrity check failed)" }]
    });

    render(<BackupsPanel />);

    await userEvent.click(await screen.findByRole("button", { name: "Restore" }));
    await userEvent.click(screen.getByRole("button", { name: "Yes, replace everything" }));

    expect(await screen.findByText(/integrity check failed/)).toBeTruthy();
  });

  it("warns when the last automatic backup failed", async () => {
    api({ "GET /api/backups": { ...LISTING, last_error: "disk full" } });

    render(<BackupsPanel />);

    expect(await screen.findByText(/automatic backup failed: disk full/)).toBeTruthy();
  });

  it("keeps its frame and says what to do when there is no copy yet", async () => {
    api({ "GET /api/backups": { ...LISTING, backups: [] } });

    render(<BackupsPanel />);

    expect(await screen.findByText(/No backups yet/)).toBeTruthy();
    expect(screen.getByRole("button", { name: "Back up now" })).toBeTruthy();
  });
});

describe("when the server cannot be reached", () => {
  it("says so in words instead of a raw browser error", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => {
      throw new TypeError("Failed to fetch");
    }));

    await expect(getJSON("/api/stats")).rejects.toThrow(/Cannot reach the server/);
  });

  it("turns a server error into a calm sentence", async () => {
    api({ "GET /api/stats": [500, {}] });

    await expect(getJSON("/api/stats")).rejects.toThrow(/server had a problem/);
  });
});

describe("the sign-in rate limit", () => {
  const AUTH = { required: true, ok: false, methods: { password: true, token: false }, signup: "closed" };

  it("pauses the button with a countdown and says how long", async () => {
    api({
      "GET /api/auth": AUTH,
      "POST /api/login": [
        429,
        { detail: "too many failed attempts; try again in 5 minutes" },
        { "Retry-After": "300" }
      ]
    });

    render(
      <LoginGate>
        <div>the dashboard</div>
      </LoginGate>
    );

    await userEvent.type(await screen.findByPlaceholderText("Username"), "alice");
    await userEvent.type(screen.getByPlaceholderText("Password"), "wrong wrong wrong");
    await userEvent.click(document.querySelector(".auth-go"));

    expect(await screen.findByText(/try again in 5 minutes/)).toBeTruthy();
    expect(await screen.findByText("5:00")).toBeTruthy();

    await waitFor(() => expect(document.querySelector(".auth-go").disabled).toBe(true));
  });

  it("explains an unreachable server on the sign-in page", async () => {
    let calls = 0;

    vi.stubGlobal("fetch", vi.fn(async (url) => {
      calls += 1;

      if (String(url).includes("/api/auth")) {
        return { ok: true, status: 200, headers: new Headers(), json: async () => AUTH };
      }

      throw new TypeError("Failed to fetch");
    }));

    render(
      <LoginGate>
        <div>the dashboard</div>
      </LoginGate>
    );

    await userEvent.type(await screen.findByPlaceholderText("Username"), "alice");
    await userEvent.type(screen.getByPlaceholderText("Password"), "correct horse battery");
    await userEvent.click(document.querySelector(".auth-go"));

    expect(await screen.findByText(/Cannot reach the server/)).toBeTruthy();
    expect(calls).toBeGreaterThan(1);
  });
});

describe("the crash screen", () => {
  it("replaces a broken dashboard with a way out", async () => {
    const quiet = vi.spyOn(console, "error").mockImplementation(() => {});

    // React rethrows a render error to the window; the test expects it, so it is not reported
    const hush = (event) => event.preventDefault();

    window.addEventListener("error", hush);

    function Broken() {
      throw new Error("boom");
    }

    render(
      <CrashScreen>
        <Broken />
      </CrashScreen>
    );

    expect(await screen.findByText("The dashboard hit a problem")).toBeTruthy();
    expect(screen.getByRole("button", { name: "Reload" })).toBeTruthy();
    expect(screen.getByText("boom")).toBeTruthy();

    window.removeEventListener("error", hush);
    quiet.mockRestore();
  });

  it("stays out of the way when nothing is wrong", () => {
    render(
      <CrashScreen>
        <div>fine</div>
      </CrashScreen>
    );

    expect(screen.getByText("fine")).toBeTruthy();
  });
});
