import { useEffect, useState } from "react";

import { disablePush, enablePush, pushState, testPush } from "../push.js";

/** Critical-alert notifications on this device, even with the dashboard closed. */
export default function PushCard() {
  const [state, setState] = useState(null);
  const [note, setNote] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const load = () =>
    pushState()
      .then(setState)
      .catch((e) => setError(e.message));

  useEffect(() => {
    load();
  }, []);

  const run = async (fn, done) => {
    setBusy(true);
    setError("");
    setNote("");

    try {
      await fn();
      setNote(done);
      await load();
    } catch (e) {
      setError(e.message);
    }

    setBusy(false);
  };

  if (!state) return <div className="card account">{error || "Loading…"}</div>;

  return (
    <div className="card account">
      <h2>
        Alerts on this device <span className={state.subscribed ? "pill on" : "pill"}>{state.subscribed ? "on" : "off"}</span>
      </h2>

      {!state.supported ? (
        <p className="muted small-text">
          This browser cannot receive push notifications. Chrome, Edge, Firefox and Safari 16.4 or newer can (on
          an iPhone, first add the dashboard to the Home Screen).
        </p>
      ) : (
        <>
          <p className="muted small-text">
            Get a notification for Critical alerts of real traffic (one per few seconds at most, never one per
            alert), even when the dashboard is closed. Messages are encrypted for this device; the browser's own
            push service cannot read them. Administrators also get security warnings, such as a locked-out account.
          </p>

          {state.permission === "denied" && (
            <div className="error">Notifications are blocked for this site; allow them in the browser's settings first.</div>
          )}

          <div className="row-actions">
            {state.subscribed ? (
              <>
                <button className="btn" disabled={busy} onClick={() => run(testPush, "Test sent. It should arrive in a moment.")}>
                  Send a test
                </button>
                <button className="btn danger" disabled={busy} onClick={() => run(disablePush, "Turned off for this device.")}>
                  Turn off
                </button>
              </>
            ) : (
              <button
                className="btn primary"
                disabled={busy || state.permission === "denied"}
                onClick={() => run(enablePush, "Turned on for this device.")}
              >
                Turn on for this device
              </button>
            )}
          </div>

          <span className="muted small-text">
            {state.devices} {state.devices === 1 ? "device" : "devices"} registered for you
          </span>
        </>
      )}

      {error && <div className="error">{error}</div>}
      {note && <div className="note">{note}</div>}
    </div>
  );
}
