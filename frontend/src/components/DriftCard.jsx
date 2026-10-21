import { useState } from "react";

import { SOURCE_LABEL } from "../theme.js";

const TONE = {
  stable: "#4cc38a",
  warning: "#f7d154",
  drift: "#ff5370",
  "warming up": "#8b95a7",
  unavailable: "#8b95a7"
};

const WORST_FIRST = (a, b) => b[1] - a[1];

/** Latest drift report of the selected source (or every source). */
export default function DriftCard({ drift, source }) {
  const [open, setOpen] = useState(false);

  const entries = Object.entries(drift).filter(
    ([name]) => source === "all" || name === source
  );

  return (
    <div className="card">
      <div className="card-head">
        <h2>Traffic drift</h2>
        <button className="btn small" onClick={() => setOpen(!open)}>
          {open ? "Hide features" : "Features"}
        </button>
      </div>

      {!entries.length && (
        <div className="empty small">Waiting for traffic.</div>
      )}

      {entries.map(([name, report]) => (
        <div key={name} className="drift">
          <div className="drift-head">
            <span className="muted">{SOURCE_LABEL[name] || name}</span>
            <span
              className="badge"
              style={{
                color: TONE[report.status],
                borderColor: TONE[report.status] + "55",
                background: TONE[report.status] + "18"
              }}
            >
              {report.status}
            </span>
          </div>

          <div className="drift-stats">
            {report.worst_feature && (
              <span>
                Worst: {report.worst_feature.replace(/_/g, " ")}
                <b> PSI {report.max_psi.toFixed(2)}</b>
              </span>
            )}
            <span>
              Anomalies {(report.anomaly_rate * 100).toFixed(2)}%
              <span className="muted">
                {" "}
                (normal {(report.expected_anomaly_rate * 100).toFixed(1)}%)
              </span>
            </span>
            <span className="muted">
              {report.flows.toLocaleString()} benign flows in window
            </span>
          </div>

          {open &&
            Object.entries(report.features || {})
              .sort(WORST_FIRST)
              .slice(0, 8)
              .map(([feature, value]) => (
                <div className="bar-row narrow" key={feature}>
                  <span>{feature.replace(/_/g, " ")}</span>
                  <div className="bar">
                    <div
                      style={{
                        width: `${Math.min(value / 0.8, 1) * 100}%`,
                        background:
                          value >= 0.6
                            ? TONE.drift
                            : value >= 0.3
                              ? TONE.warning
                              : TONE.stable
                      }}
                    />
                  </div>
                  <span className="mono">{value.toFixed(2)}</span>
                </div>
              ))}
        </div>
      ))}
    </div>
  );
}
