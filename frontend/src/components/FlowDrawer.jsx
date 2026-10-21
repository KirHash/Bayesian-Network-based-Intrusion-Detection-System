import { useEffect, useState } from "react";

import { getJSON } from "../api.js";

import { RISK_COLOR, typeColor } from "../theme.js";

export default function FlowDrawer({ flowId, onClose }) {
  const [flow, setFlow] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    if (flowId === null) return;

    setFlow(null);
    setError(null);

    getJSON(`/api/flows/${flowId}`)
      .then(setFlow)
      .catch(() => setError("This flow has left the server's buffer."));
  }, [flowId]);

  useEffect(() => {
    const onKey = (e) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  if (flowId === null) return null;

  const posterior = flow
    ? Object.entries(flow.posterior).sort((a, b) => b[1] - a[1])
    : [];

  return (
    <>
      <div className="scrim" onClick={onClose} />

      <aside className="drawer">
        <div className="card-head">
          <h2>Flow #{flowId}</h2>
          <button className="btn" onClick={onClose}>
            Close
          </button>
        </div>

        {error && <div className="empty">{error}</div>}

        {flow && (
          <>
            <div className="verdict">
              <span
                className="big"
                style={{ color: typeColor(flow.attack_type) }}
              >
                {flow.attack_type}
              </span>
              <span style={{ color: RISK_COLOR[flow.risk] }}>
                {flow.risk} · {flow.probability.toFixed(2)}% intrusion
              </span>
              {flow.label !== null && (
                <span className="muted">Ground truth: {flow.label}</span>
              )}
            </div>

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
                {Object.entries(flow.features).map(([name, value]) => (
                  <tr key={name}>
                    <td>{name}</td>
                    <td className="r mono">{value.toLocaleString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </>
        )}
      </aside>
    </>
  );
}
