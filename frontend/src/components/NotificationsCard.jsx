import { useEffect, useState } from "react";

import { getJSON, send } from "../api.js";
import { useAuth } from "../auth.js";

const permission = () =>
  typeof Notification === "undefined" ? "unsupported" : Notification.permission;

export default function NotificationsCard({ browserAlerts, onBrowserAlerts }) {
  const [info, setInfo] = useState(null);
  const [message, setMessage] = useState("");
  const { isAdmin } = useAuth();

  const load = () =>
    getJSON("/api/notifications")
      .then(setInfo)
      .catch(() => {});

  useEffect(() => {
    load();
    const timer = setInterval(load, 15000);
    return () => clearInterval(timer);
  }, []);

  const test = async () => {
    setMessage("Sending…");

    try {
      const result = await send("/api/notifications/test", "POST");

      setMessage(
        Object.entries(result)
          .map(([channel, r]) => `${channel}: ${r.ok ? "sent" : r.error}`)
          .join(" · ")
      );
    } catch (error) {
      setMessage(error.message);
    }

    load();
  };

  const toggleBrowser = async () => {
    if (browserAlerts) return onBrowserAlerts(false);

    if (permission() === "default") await Notification.requestPermission();

    onBrowserAlerts(permission() === "granted");
  };

  return (
    <div className="card">
      <div className="card-head">
        <h2>Notifications</h2>
        {isAdmin && (
          <div className="filters">
            <button
              className="btn small"
              onClick={test}
              disabled={!info?.channels.length}
            >
              Send test
            </button>
          </div>
        )}
      </div>

      {info?.problem && <div className="error">{info.problem}</div>}

      {info && !info.channels.length && !info.problem && (
        <div className="muted small-text">
          No channel configured.
          {isAdmin && " Set one up under Operations."}
        </div>
      )}

      {info?.channels.length > 0 && (
        <div className="small-text">
          {info.channels.join(" + ")} · {info.min_risk}+ alerts from{" "}
          {info.sources.join(", ")} · digest every {info.window_seconds}s
        </div>
      )}

      {message && <div className="small-text muted">{message}</div>}

      <label className="check">
        <input
          type="checkbox"
          checked={browserAlerts}
          onChange={toggleBrowser}
          disabled={permission() === "unsupported" || permission() === "denied"}
        />
        Browser notifications for Critical alerts
        {permission() === "denied" && (
          <span className="muted"> (blocked in browser settings)</span>
        )}
      </label>

      {info?.recent.length > 0 && (
        <ul className="log">
          {info.recent.slice(0, 4).map((n, i) => (
            <li key={i} className={n.ok ? "" : "miss"}>
              <span className="mono">{n.time.slice(11)}</span> {n.channel}{" "}
              {n.ok ? `sent (${n.alerts} alerts)` : `failed: ${n.detail}`}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
