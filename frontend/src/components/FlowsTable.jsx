import { useState } from "react";

import { getJSON } from "../api.js";
import { useRefresh } from "../useLive.js";
import { RISK_COLOR, typeColor } from "../theme.js";
import { Badge } from "./AlertTable.jsx";

const where = (flow) =>
  flow.src_ip
    ? `${flow.src_ip} → ${flow.dst_ip}:${flow.dst_port}`
    : `port ${flow.dst_port}`;

/** Every recently scored flow, benign ones too: proof that traffic arrives. */
export default function FlowsTable({ source, revision, onSelect }) {
  const [verdict, setVerdict] = useState("all");
  const [rows, setRows] = useState([]);
  const [error, setError] = useState(null);

  const load = () =>
    getJSON(`/api/flows?source=${source}&verdict=${verdict}&limit=100`)
      .then((data) => {
        setRows(data);
        setError(null);
      })
      .catch(() => setError("Could not load flows."));

  useRefresh(load, [source, verdict], revision, 1000);

  return (
    <div className="card">
      <div className="card-head">
        <h2>Recent flows</h2>

        <div className="filters">
          <select value={verdict} onChange={(e) => setVerdict(e.target.value)}>
            <option value="all">Benign and attacks</option>
            <option value="benign">Benign only</option>
            <option value="attack">Attacks only</option>
          </select>
        </div>
      </div>

      <div className="muted small-text">
        The newest scored flows, newest first. Benign flows are not stored,
        only counted, so this list lives in memory and is cleared on restart.
      </div>

      {error && <div className="error">{error}</div>}

      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Time</th>
              <th>Source</th>
              <th>Flow</th>
              <th>Verdict</th>
              <th className="r">Intrusion</th>
              <th>Risk</th>
            </tr>
          </thead>

          <tbody>
            {rows.map((f, i) => (
              <tr
                key={i}
                className={f.alert_id ? "" : "dim"}
                onClick={() => f.alert_id && onSelect(f.alert_id)}
                style={{ cursor: f.alert_id ? "pointer" : "default" }}
              >
                <td className="mono">{f.time.slice(11)}</td>
                <td>{f.source}</td>
                <td className="mono">{where(f)}</td>
                <td>
                  {f.prediction === "ATTACK" ? (
                    <Badge color={typeColor(f.attack_type)}>
                      {f.attack_type}
                    </Badge>
                  ) : (
                    <span className="ok">benign</span>
                  )}
                </td>
                <td className="r mono">{f.probability.toFixed(2)}%</td>
                <td>
                  {f.prediction === "ATTACK" ? (
                    <Badge color={RISK_COLOR[f.risk]}>{f.risk}</Badge>
                  ) : (
                    <span className="muted">–</span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>

        {!rows.length && (
          <div className="empty">
            No flows yet for this source. See Sources on the right.
          </div>
        )}
      </div>
    </div>
  );
}
