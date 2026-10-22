import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import PushCard from "../src/components/PushCard.jsx";
import { disablePush, enablePush, keyBytes, pushState, pushSupported } from "../src/push.js";
import { api } from "./helpers.js";

const KEY = "BEl62iUYgUivxIkv69yViEuiBIa-Ib9-SkvMeAtA3LFgDzkrxZJjSgSnfckjBJuBkr3qBUYIHBQFLXYp5Nksh8U";

/** A browser that supports push: a service worker, a push manager and the Notification API. */
function browser({ permission = "default", grant = "granted", subscribed = false } = {}) {
  let subscription = subscribed
    ? { endpoint: "https://fcm.googleapis.com/fcm/send/abc", toJSON: () => ({ endpoint: "https://fcm.googleapis.com/fcm/send/abc", keys: { p256dh: "p", auth: "a" } }), unsubscribe: vi.fn(async () => true) }
    : null;

  const pushManager = {
    getSubscription: vi.fn(async () => subscription),
    subscribe: vi.fn(async (options) => {
      subscription = {
        endpoint: "https://fcm.googleapis.com/fcm/send/new",
        options,
        toJSON: () => ({ endpoint: "https://fcm.googleapis.com/fcm/send/new", keys: { p256dh: "p", auth: "a" } }),
        unsubscribe: vi.fn(async () => true)
      };

      return subscription;
    })
  };

  const registration = { pushManager };

  vi.stubGlobal("Notification", { permission, requestPermission: vi.fn(async () => grant) });
  vi.stubGlobal("PushManager", function PushManager() {});

  Object.defineProperty(navigator, "serviceWorker", {
    configurable: true,
    value: {
      register: vi.fn(async () => registration),
      ready: Promise.resolve(registration),
      getRegistration: vi.fn(async () => registration)
    }
  });

  return { pushManager, current: () => subscription };
}

function noBrowserSupport() {
  Object.defineProperty(navigator, "serviceWorker", { configurable: true, value: undefined });
  delete navigator.serviceWorker;
}

describe("the server's key", () => {
  it("is turned into the bytes a browser wants", () => {
    const bytes = keyBytes(KEY);

    expect(bytes).toBeInstanceOf(Uint8Array);
    expect(bytes).toHaveLength(65);
    expect(bytes[0]).toBe(4);
  });
});

describe("push in the browser", () => {
  it("knows when the browser cannot do it", async () => {
    noBrowserSupport();

    expect(pushSupported()).toBe(false);
    expect(await pushState()).toEqual({ supported: false });
  });

  it("subscribes with the server's key and tells the server", async () => {
    const { pushManager } = browser();

    const { calls } = api({
      "GET /api/push": { public_key: KEY, devices: 0 },
      "POST /api/push/subscribe": { devices: 1 }
    });

    expect(await enablePush()).toBe(1);

    const options = pushManager.subscribe.mock.calls[0][0];

    // visible notifications only, with the server's identity
    expect(options.userVisibleOnly).toBe(true);
    expect(options.applicationServerKey).toHaveLength(65);

    expect(calls.find((c) => c.path === "/api/push/subscribe").body.subscription.endpoint).toContain("fcm.googleapis.com");
  });

  it("does nothing, and says why, when the person refuses permission", async () => {
    const { pushManager } = browser({ grant: "denied" });

    const { calls } = api({});

    await expect(enablePush()).rejects.toThrow(/blocked/);

    expect(pushManager.subscribe).not.toHaveBeenCalled();
    expect(calls).toHaveLength(0);
  });

  it("reuses a subscription the browser already has", async () => {
    const { pushManager } = browser({ subscribed: true });

    api({ "GET /api/push": { public_key: KEY, devices: 1 }, "POST /api/push/subscribe": { devices: 1 } });

    await enablePush();

    expect(pushManager.subscribe).not.toHaveBeenCalled();
  });

  it("unsubscribes the browser and the server", async () => {
    const { current } = browser({ subscribed: true });

    const sub = current();

    const { calls } = api({ "POST /api/push/unsubscribe": { devices: 0 } });

    await disablePush();

    expect(calls[0].body).toEqual({ endpoint: "https://fcm.googleapis.com/fcm/send/abc" });
    expect(sub.unsubscribe).toHaveBeenCalled();
  });
});

describe("the card", () => {
  it("explains when push is not possible", async () => {
    noBrowserSupport();

    api({});

    render(<PushCard />);

    expect(await screen.findByText(/cannot receive push notifications/)).toBeTruthy();
    expect(screen.queryByRole("button", { name: /Turn on/ })).toBeNull();
  });

  it("turns it on, then offers a test and turning off", async () => {
    browser();

    let devices = 0;

    api({
      "GET /api/push": () => ({ public_key: KEY, devices }),
      "POST /api/push/subscribe": () => {
        devices = 1;

        return { devices };
      },
      "POST /api/push/test": { sent: 1, gone: 0, failed: 0 }
    });

    render(<PushCard />);

    await userEvent.click(await screen.findByRole("button", { name: "Turn on for this device" }));

    expect(await screen.findByText("Turned on for this device.")).toBeTruthy();
    expect(await screen.findByRole("button", { name: "Send a test" })).toBeTruthy();
    expect(screen.getByText("1 device registered for you")).toBeTruthy();

    await userEvent.click(screen.getByRole("button", { name: "Send a test" }));

    expect(await screen.findByText(/Test sent/)).toBeTruthy();
  });

  it("will not offer to turn on when notifications are blocked for the site", async () => {
    browser({ permission: "denied" });

    api({ "GET /api/push": { public_key: KEY, devices: 0 } });

    render(<PushCard />);

    expect(await screen.findByText(/blocked for this site/)).toBeTruthy();

    await waitFor(() => expect(screen.getByRole("button", { name: "Turn on for this device" }).disabled).toBe(true));
  });

  it("shows the server's refusal", async () => {
    browser();

    api({
      "GET /api/push": { public_key: KEY, devices: 0 },
      "POST /api/push/subscribe": [400, { detail: "that push service is not one this server sends to" }]
    });

    render(<PushCard />);

    await userEvent.click(await screen.findByRole("button", { name: "Turn on for this device" }));

    expect(await screen.findByText(/not one this server sends to/)).toBeTruthy();
  });
});
