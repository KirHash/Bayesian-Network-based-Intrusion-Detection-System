/* Shows Critical-alert notifications sent by the server, even when the dashboard is closed. */

self.addEventListener("install", () => self.skipWaiting());

self.addEventListener("activate", (event) => event.waitUntil(self.clients.claim()));

self.addEventListener("push", (event) => {
  let message = { title: "Bayesian IDS", body: "", url: "/", tag: "ids" };

  try {
    message = { ...message, ...event.data.json() };
  } catch {
    message.body = event.data ? event.data.text() : "";
  }

  event.waitUntil(
    self.registration.showNotification(message.title, {
      body: message.body,
      tag: message.tag,
      renotify: true,
      data: { url: message.url }
    })
  );
});

// a tap opens the alert: in the open dashboard if there is one, else in a new window
self.addEventListener("notificationclick", (event) => {
  event.notification.close();

  const url = new URL((event.notification.data && event.notification.data.url) || "/", self.location.origin).href;

  event.waitUntil(
    (async () => {
      const windows = await self.clients.matchAll({ type: "window", includeUncontrolled: true });

      for (const client of windows) {
        if ("focus" in client) {
          await client.focus();

          if ("navigate" in client) await client.navigate(url).catch(() => {});

          return;
        }
      }

      await self.clients.openWindow(url);
    })()
  );
});
