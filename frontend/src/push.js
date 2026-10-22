import { getJSON, send } from "./api.js";

/** Whether this browser can receive push notifications at all. */
export const pushSupported = () =>
  typeof window !== "undefined" &&
  "serviceWorker" in navigator &&
  "PushManager" in window &&
  "Notification" in window;

/** The server's public key as the bytes pushManager.subscribe wants. */
export function keyBytes(text) {
  const padded = text + "=".repeat((4 - (text.length % 4)) % 4);

  const raw = atob(padded.replace(/-/g, "+").replace(/_/g, "/"));

  return Uint8Array.from(raw, (c) => c.charCodeAt(0));
}

async function worker() {
  await navigator.serviceWorker.register("/sw.js");

  return navigator.serviceWorker.ready;
}

/** What this device has: the browser's subscription, if any, and the server's view. */
export async function pushState() {
  if (!pushSupported()) return { supported: false };

  const registration = await navigator.serviceWorker.getRegistration("/sw.js").catch(() => null);

  const subscription = registration ? await registration.pushManager.getSubscription() : null;

  const server = await getJSON("/api/push");

  return {
    supported: true,
    permission: Notification.permission,
    subscribed: !!subscription,
    devices: server.devices
  };
}

/** Ask for permission, subscribe this browser and tell the server. Returns the server's device count. */
export async function enablePush() {
  const permission = await Notification.requestPermission();

  if (permission !== "granted") {
    throw new Error("Notifications are blocked for this site. Allow them in the browser's address bar settings.");
  }

  const { public_key: key } = await getJSON("/api/push");

  const registration = await worker();

  const subscription =
    (await registration.pushManager.getSubscription()) ||
    (await registration.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: keyBytes(key) }));

  return (await send("/api/push/subscribe", "POST", { subscription: subscription.toJSON() })).devices;
}

export async function disablePush() {
  const registration = await navigator.serviceWorker.getRegistration("/sw.js");

  const subscription = registration ? await registration.pushManager.getSubscription() : null;

  if (subscription) {
    await send("/api/push/unsubscribe", "POST", { endpoint: subscription.endpoint });
    await subscription.unsubscribe();
  }
}

export const testPush = () => send("/api/push/test", "POST");
