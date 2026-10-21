import { useEffect, useState } from "react";

import { getJSON, send } from "../api.js";
import { useAuth } from "../auth.js";
import {
  RISK_COLOR,
  STATUS_COLOR,
  STATUS_LABEL,
  typeColor
} from "../theme.js";

const REASON = {
  classifier: "The network is confident this is not benign traffic.",
  anomaly:
    "The classifier called it benign, but it is far less likely than normal traffic. Something unfamiliar, not a known attack."
};

export default function AlertDrawer({ alertId, revision, onClose }) {
  const [alert, setAlert] = useState(null);
  const [error, setError] = useState(null);
  const [assignee, setAssignee] = useState("");
  const [note, setNote] = useState("");
  const [saving, setSaving] = useState(false);
  const { canHandle } = useAuth();

  // fields=true also resets the inputs; background refreshes must not
  // overwrite a note that is being typed
  const load = (fields) =>
    getJSON(`/api/alerts/${alertId}`)
      .then((data) => {
        setAlert(data);

        if (fields) {
          setAssignee(data.assignee || "");
          setNote(data.note || "");
        }

        setError(null);
      })
      .catch(() => setError("This alert no longer exists."));

  useEffect(() => {
    if (alertId === null) return;
    setAlert(null);
    load(true);
  }, [alertId]);

  useEffect(() => {
    if (alertId !== null && alert) load(false);
  }, [revision]);

  useEffect(() => {
    const onKey = (e) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  if (alertId === null) return null;

  const update = async (changes) => {
    setSaving(true);

    try {
      const updated = await send(`/api/alerts/${alertId}`, "PATCH", changes);

      setAlert(updated);
      setError(null);
    } catch (e) {
      setError(e.message);
    }

    setSaving(false);
  };

  const posterior = alert?.posterior
    ? Object.entries(alert.posterior).sort((a, b) => b[1] - a[1])
    : [];

  return (
    <>
      <div className="scrim" onClick={onClose} />

      <aside className="drawer">
        <div className="card-head">
          <h2>Alert #{alertId}</h2>
          <button className="btn" onClick={onClose}>
            Close
          </button>
        </div>

        {error && <div className="error">{error}</div>}

        {alert && (
          <>
            <div className="verdict">
              <span className="big" style={{ color: typeColor(alert.attack_type) }}>
                {alert.attack_type}
              </span>
              <span style={{ color: RISK_COLOR[alert.risk] }}>
                {alert.risk} · {alert.probability.toFixed(2)}% intrusion
              </span>
              <span className="muted">
                {alert.time.replace("T", " ")} · {alert.source}
              </span>
              {alert.src_ip && (
                <span className="mono">
                  {alert.src_ip} → {alert.dst_ip}:{alert.dst_port}
                </span>
              )}
              {alert.label !== null && (
                <span className="muted">Ground truth: {alert.label}</span>
              )}
              <span className="muted small-text">{REASON[alert.reason]}</span>
            </div>

            <h3>Handling</h3>

            <div className="status-buttons">
              {Object.entries(STATUS_LABEL).map(([value, label]) => (
                <button
                  key={value}
                  disabled={saving || !canHandle}
                  className={`btn small ${alert.status === value ? "active" : ""}`}
                  style={
                    alert.status === value
                      ? {
                          borderColor: STATUS_COLOR[value],
                          color: STATUS_COLOR[value]
                        }
                      : undefined
                  }
                  onClick={() => update({ status: value })}
                >
                  {label}
                </button>
              ))}
            </div>

            <label className="stack">
              <span>Assignee</span>
              <input
                value={assignee}
                disabled={!canHandle}
                placeholder="Unassigned"
                onChange={(e) => setAssignee(e.target.value)}
                onBlur={() =>
                  assignee !== (alert.assignee || "") && update({ assignee })
                }
              />
            </label>

            <label className="stack">
              <span>Note</span>
              <textarea
                rows={3}
                value={note}
                disabled={!canHandle}
                placeholder="What did you find?"
                onChange={(e) => setNote(e.target.value)}
                onBlur={() => note !== (alert.note || "") && update({ note })}
              />
            </label>

            <h3>Class probabilities</h3>

            {posterior.map(([name, p]) => (
              <div className="bar-row" key={name}>
                <span>{name}</span>
                <div className="bar">
                  <div
                    style={{
                      width: `${Math.max(p * 100, p > 0 ? 0.5 : 0)}%`,
                      background: typeColor(name)
                    }}
                  />
                </div>
                <span className="mono">{(p * 100).toFixed(2)}%</span>
              </div>
            ))}

            <h3>Flow features</h3>

            <table className="kv">
              <tbody>
                {Object.entries(alert.features || {}).map(([name, value]) => (
                  <tr key={name}>
                    <td>{name}</td>
                    <td className="r mono">{value.toLocaleString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>

            <h3>History</h3>

            {alert.events.length === 0 && (
              <div className="muted small-text">No changes yet.</div>
            )}

            <ul className="log">
              {alert.events.map((e, i) => (
                <li key={i}>
                  <span className="mono">{e.time.replace("T", " ")}</span>{" "}
                  <b>{e.actor}</b> {e.action}: {e.detail}
                </li>
              ))}
            </ul>
          </>
        )}
      </aside>
    </>
  );
}
