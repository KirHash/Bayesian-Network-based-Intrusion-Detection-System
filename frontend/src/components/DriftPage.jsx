import { useState } from "react";
import {
  CartesianGrid,
  Line,
  LineChart,
  ReferenceLine,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis
} from "recharts";

import { getJSON } from "../api.js";
import { SOURCE_LABEL } from "../theme.js";
import { useRefresh } from "../useLive.js";

export const TONE = {
  stable: "#44a282",
  warning: "#d9a441",
  drift: "#e5566f",
  "warming up": "#8e94b8",
  unavailable: "#8e94b8"
};

// PSI levels at which a feature is flagged (the dashboard's bars use the same)
const WARN = 0.3;
const ALARM = 0.6;

const ADVICE = {
  stable: "Normal traffic looks like the traffic the model learned from. Nothing to do.",
  warning:
    "Some features of normal traffic have shifted. Alerts are still meaningful, but watch the worst feature below; if it keeps climbing, retrain.",
  drift:
    "Normal traffic here no longer looks like the training data, so both false alarms and misses become more likely. Retrain with data from this network (Operations → Model), or check that the source is sending what you expect.",
  "warming up": "Not enough normal flows have been seen yet to compare with the training data.",
  unavailable: "This model has no reference traffic to compare against. Retrain to get one."
};

const AXIS = { stroke: "#8a8c92", fontSize: 11 };

const TOOLTIP = {
  contentStyle: { background: "#212023", border: "1px solid #3a3a3e", borderRadius: 6, fontSize: 12 }
};

const feature = (name) => name.replace(/_/g, " ");

function Trend({ title, points, field, unit, lines, empty }) {
  const data = points
    .filter((p) => p[field] !== null && p[field] !== undefined)
    .map((p) => ({ t: p.t, value: unit === "%" ? p[field] * 100 : p[field] }));

  return (
    <div className="trend">
      <div className="muted small-text">{title}</div>

      {data.length < 2 ? (
        <div className="empty small">{empty}</div>
      ) : (
        <ResponsiveContainer width="100%" height={150}>
          <LineChart data={data} margin={{ left: -14, right: 8, top: 8 }}>
            <CartesianGrid stroke="#2b2b2b" vertical={false} />
            <XAxis dataKey="t" {...AXIS} minTickGap={50} />
            <YAxis {...AXIS} domain={[0, "auto"]} />
            <Tooltip {...TOOLTIP} formatter={(v) => `${v.toFixed(unit === "%" ? 2 : 2)}${unit === "%" ? "%" : ""}`} />
            {lines.map(([y, label, color]) => (
              <ReferenceLine key={label} y={y} stroke={color} strokeDasharray="4 4" label={{ value: label, fill: color, fontSize: 10, position: "insideTopRight" }} />
            ))}
            <Line type="linear" dataKey="value" stroke="#f2f2f3" strokeWidth={2} dot={false} isAnimationActive={false} />
          </LineChart>
        </ResponsiveContainer>
      )}
    </div>
  );
}

function SourceDrift({ name, report, points }) {
  const color = TONE[report.status] || TONE.unavailable;

  const features = Object.entries(report.features || {}).sort((a, b) => b[1] - a[1]);

  return (
    <section className="card drift-source">
      <div className="card-head">
        <h2>{SOURCE_LABEL[name] || name}</h2>

        <span className="badge" style={{ color, borderColor: color + "55", background: color + "18" }}>
          {report.status}
        </span>
      </div>

      <p className="muted">{ADVICE[report.status] || ADVICE.unavailable}</p>

      <div className="drift-numbers">
        <div className="figure">
          <span>Worst feature</span>
          <b>{report.worst_feature ? feature(report.worst_feature) : "–"}</b>
          <em>{report.max_psi !== undefined ? `PSI ${report.max_psi.toFixed(2)}` : "not yet measured"}</em>
        </div>

        <div className="figure">
          <span>Unfamiliar flows</span>
          <b>{report.anomaly_rate !== undefined ? `${(report.anomaly_rate * 100).toFixed(2)}%` : "–"}</b>
          <em>
            normal is {report.expected_anomaly_rate !== undefined ? `${(report.expected_anomaly_rate * 100).toFixed(1)}%` : "–"}
          </em>
        </div>

        <div className="figure">
          <span>Compared on</span>
          <b>{(report.flows || 0).toLocaleString()}</b>
          <em>normal flows in the window</em>
        </div>
      </div>

      <div className="trends">
        <Trend
          title="Worst feature over time (PSI)"
          points={points}
          field="max_psi"
          unit=""
          lines={[[WARN, "watch", TONE.warning], [ALARM, "drift", TONE.drift]]}
          empty="Builds up while traffic flows."
        />

        <Trend
          title="Unfamiliar flows over time (%)"
          points={points}
          field="anomaly_rate"
          unit="%"
          lines={report.expected_anomaly_rate ? [[report.expected_anomaly_rate * 100, "normal", TONE.stable]] : []}
          empty="Builds up while traffic flows."
        />
      </div>

      {features.length > 0 && (
        <>
          <h3>Every feature, most changed first</h3>

          <div className="drift-features">
            {features.map(([name, value]) => (
              <div className="bar-row narrow" key={name}>
                <span>{feature(name)}</span>
                <div className="bar">
                  <div
                    style={{
                      width: `${Math.min(value / 0.8, 1) * 100}%`,
                      background: value >= ALARM ? TONE.drift : value >= WARN ? TONE.warning : TONE.stable
                    }}
                  />
                </div>
                <span className="mono">{value.toFixed(2)}</span>
              </div>
            ))}
          </div>
        </>
      )}
    </section>
  );
}

/** Whether normal traffic still looks like what the model was trained on. */
export default function DriftPage({ drift, source, revision }) {
  const [history, setHistory] = useState({});

  useRefresh(
    () =>
      getJSON(`/api/drift/history?source=${source}`)
        .then(setHistory)
        .catch(() => {}),
    [source],
    revision,
    5000
  );

  const entries = Object.entries(drift || {}).filter(([name]) => source === "all" || name === source);

  return (
    <div className="drift-page">
      <section className="card">
        <h2>What drift means</h2>

        <p className="muted">
          The model learned what normal traffic looks like from its training data. If your normal traffic changes
          (new software, a different network, a seasonal peak), its judgements get less reliable without any
          error showing. This page compares each feature of the normal flows now arriving with the training data
          (the population stability index, PSI: below {WARN} is fine, above {ALARM} is a real shift) and watches how
          many flows look unfamiliar. Only flows judged benign are compared, so an attack does not read as drift.
        </p>
      </section>

      {entries.length === 0 && (
        <section className="card">
          <div className="empty">Nothing to compare yet. Drift appears once traffic has been scored.</div>
        </section>
      )}

      {entries.map(([name, report]) => (
        <SourceDrift key={name} name={name} report={report} points={history[name] || []} />
      ))}
    </div>
  );
}
