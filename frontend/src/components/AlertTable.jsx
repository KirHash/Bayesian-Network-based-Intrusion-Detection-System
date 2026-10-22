import { useCallback, useState } from "react";

import { getJSON, send } from "../api.js";
import { useAuth } from "../auth.js";
import AlertViews from "./AlertViews.jsx";
import { useRefresh } from "../useLive.js";
import {
  RISK_COLOR,
  RISK_ORDER,
  STATUS_COLOR,
  STATUS_LABEL,
  typeColor
} from "../theme.js";

const PAGE = 100;

export function Badge({ color, children }) {
  return (
    <span
      className="badge"
      style={{ color, borderColor: color + "55", background: color + "18" }}
    >
      {children}
    </span>
  );
}

/** Green when the verdict matches the replay ground truth, red when not. */
function Verdict({ alert }) {
  if (alert.label === null) return <span className="muted">–</span>;

  const hit = alert.label !== "BENIGN";

  return (
    <span className={hit ? "ok" : "miss"} title={`Ground truth: ${alert.label}`}>
      {alert.label}
    </span>
  );
}

const where = (alert) =>
  alert.src_ip
    ? `${alert.src_ip} → ${alert.dst_ip}:${alert.dst_port}`
    : `port ${alert.dst_port}`;

export default function AlertTable({
  source,
  revision,
  selected,
  onSelect,
  types,
  flowsScored,
  onShowFlows
}) {
  const [status, setStatus] = useState("open");
  const [risk, setRisk] = useState("all");
  const [type, setType] = useState("all");
  const [query, setQuery] = useState("");
  const [rows, setRows] = useState([]);
  const [more, setMore] = useState(false);
  const [checked, setChecked] = useState(new Set());
  const [error, setError] = useState(null);
  const { canHandle } = useAuth();

  const params = useCallback(
    (extra = {}) =>
      new URLSearchParams({
        status,
        limit: PAGE,
        ...(risk !== "all" && { risk }),
        ...(type !== "all" && { attack_type: type }),
        ...(source !== "all" && { source }),
        ...(query.trim() && { q: query.trim() }),
        ...extra
      }),
    [status, risk, type, source, query]
  );

  const load = () =>
    getJSON(`/api/alerts?${params()}`)
      .then((data) => {
        setRows(data);
        setMore(data.length === PAGE);
        setError(null);
      })
      .catch(() => setError("Could not load alerts."));

  useRefresh(load, [status, risk, type, source, query], revision);

  const loadMore = () =>
    getJSON(`/api/alerts?${params({ before_id: rows[rows.length - 1].id })}`)
      .then((data) => {
        setRows((r) => [...r, ...data]);
        setMore(data.length === PAGE);
      })
      .catch(() => setError("Could not load more alerts."));

  const toggle = (id) =>
    setChecked((current) => {
      const next = new Set(current);
      next.has(id) ? next.delete(id) : next.add(id);
      return next;
    });

  const allChecked = rows.length > 0 && rows.every((r) => checked.has(r.id));

  const bulk = async (newStatus) => {
    try {
      await send("/api/alerts/bulk", "POST", {
        ids: [...checked],
        status: newStatus
      });
      setChecked(new Set());
      load();
    } catch (e) {
      setError(e.message);
    }
  };

  return (
    <div className="card">
      <div className="card-head">
        <h2>Alerts</h2>

        <div className="filters">
          <input
            className="search"
            placeholder="Search id, IP, note…"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
          />

          <select value={status} onChange={(e) => setStatus(e.target.value)}>
            <option value="open">Open</option>
            <option value="all">All statuses</option>
            {Object.entries(STATUS_LABEL).map(([value, label]) => (
              <option key={value} value={value}>
                {label}
              </option>
            ))}
          </select>

          <select value={risk} onChange={(e) => setRisk(e.target.value)}>
            <option value="all">All risks</option>
            {RISK_ORDER.filter((r) => r !== "Low").map((r) => (
              <option key={r}>{r}</option>
            ))}
          </select>

          <select value={type} onChange={(e) => setType(e.target.value)}>
            <option value="all">All types</option>
            {types.map((t) => (
              <option key={t}>{t}</option>
            ))}
          </select>
        </div>
      </div>

      <AlertViews
        current={{ status, risk, type, query }}
        source={source}
        onApply={(view) => {
          setStatus(view.status);
          setRisk(view.risk);
          setType(view.type);
          setQuery(view.query);
        }}
      />

      {canHandle && checked.size > 0 && (
        <div className="bulk">
          <span>{checked.size} selected</span>
          <button className="btn small" onClick={() => bulk("investigating")}>
            Investigating
          </button>
          <button className="btn small" onClick={() => bulk("resolved")}>
            Resolved
          </button>
          <button className="btn small" onClick={() => bulk("false_positive")}>
            False positive
          </button>
          <button className="btn small" onClick={() => setChecked(new Set())}>
            Clear
          </button>
        </div>
      )}

      {error && <div className="error">{error}</div>}

      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>
                {canHandle && (
                  <input
                    type="checkbox"
                    checked={allChecked}
                    onChange={() =>
                      setChecked(
                        allChecked ? new Set() : new Set(rows.map((r) => r.id))
                      )
                    }
                  />
                )}
              </th>
              <th>Alert</th>
              <th>Time</th>
              <th>Type</th>
              <th>Risk</th>
              <th className="r">Confidence</th>
              <th>Flow</th>
              <th>Status</th>
              <th>Ground truth</th>
            </tr>
          </thead>

          <tbody>
            {rows.map((a) => (
              <tr
                key={a.id}
                className={a.id === selected ? "selected" : ""}
                onClick={() => onSelect(a.id)}
              >
                <td onClick={(e) => e.stopPropagation()}>
                  {canHandle && (
                    <input
                      type="checkbox"
                      checked={checked.has(a.id)}
                      onChange={() => toggle(a.id)}
                    />
                  )}
                </td>
                <td className="mono">#{a.id}</td>
                <td className="mono">{a.time.slice(11)}</td>
                <td>
                  <Badge color={typeColor(a.attack_type)}>{a.attack_type}</Badge>
                </td>
                <td>
                  <Badge color={RISK_COLOR[a.risk]}>{a.risk}</Badge>
                </td>
                <td className="r mono">{a.probability.toFixed(2)}%</td>
                <td className="mono">{where(a)}</td>
                <td>
                  <Badge color={STATUS_COLOR[a.status]}>
                    {STATUS_LABEL[a.status]}
                  </Badge>
                  {a.assignee && <span className="muted"> {a.assignee}</span>}
                </td>
                <td>
                  <Verdict alert={a} />
                </td>
              </tr>
            ))}
          </tbody>
        </table>

        {!rows.length && (
          <div className="empty">
            {flowsScored > 0 && status === "open" && query === "" ? (
              <span>
                No open alerts. {flowsScored.toLocaleString()} flows have been
                scored and none were flagged, so all of them were judged
                benign.{" "}
                <button className="link" onClick={onShowFlows}>
                  Show recent flows
                </button>
              </span>
            ) : (
              "No alerts match."
            )}
          </div>
        )}
      </div>

      {more && (
        <div className="more">
          <button className="btn" onClick={loadMore}>
            Load older alerts
          </button>
        </div>
      )}
    </div>
  );
}
