import { Cell, Pie, PieChart, ResponsiveContainer, Tooltip } from "recharts";

import { RISK_COLOR, STATUS_COLOR, STATUS_LABEL, num, pct, typeColor } from "../theme.js";
import { Timeline } from "./Charts.jsx";
import DriftCard from "./DriftCard.jsx";
import Icon from "./Icons.jsx";
import NotificationsCard from "./NotificationsCard.jsx";
import SourcesCard from "./SourcesCard.jsx";

const CLASSES = ["DDoS", "PortScan", "Web Attack", "Bot", "Anomaly"];

const BANDS = ["Critical", "High", "Medium"];

const TOOLTIP = {
  contentStyle: {
    background: "#212023",
    border: "1px solid #3a3a3e",
    borderRadius: 6,
    fontSize: 12
  }
};

const open = (stats) => (stats?.by_status?.new || 0) + (stats?.by_status?.investigating || 0);

/** The sentence at the top: what needs attention right now. */
function Hero({ stats, onOpenAlerts }) {
  if (!stats) return <section className="hero" />;

  const critical = stats.by_risk?.Critical || 0;
  const waiting = open(stats);
  const rate = stats.total ? stats.alerts / stats.total : null;

  const headline = waiting
    ? `${num(waiting)} alert${waiting === 1 ? "" : "s"} need attention`
    : stats.total
    ? "All quiet. Nothing is waiting for you."
    : "Waiting for traffic";

  return (
    <section className="hero">
      <div className="hero-text">
        <div className="hero-title">
          <h2>{headline}</h2>
          <span className={`hero-state ${waiting ? "warn" : "calm"}`}>{waiting ? "Attention" : "Clear"}</span>
        </div>

        <p>
          {critical ? `${num(critical)} of them rated Critical. ` : ""}
          {stats.total
            ? `${num(stats.total)} flows scored, ${num(stats.alerts)} flagged (${pct(rate, 2)}).`
            : "Start the demo, a live capture, or send flows to the API to see results here."}
        </p>

        {!!waiting && (
          <button className="btn primary" onClick={onOpenAlerts}>
            Review alerts
          </button>
        )}
      </div>

      <div className="hero-figures">
        <Figure label="Flows scored" value={num(stats.total)} />
        <Figure label="Alerts" value={num(stats.alerts)} />
        <Figure
          label="Precision"
          value={pct(stats.precision)}
          hint={stats.labelled ? `${num(stats.labelled)} labelled` : "needs labels"}
        />
        <Figure label="Recall" value={pct(stats.recall)} hint={`false alarms ${pct(stats.false_alarm_rate, 2)}`} />
      </div>
    </section>
  );
}

function Figure({ label, value, hint }) {
  return (
    <div className="figure">
      <span>{label}</span>
      <b>{value}</b>
      {hint && <em>{hint}</em>}
    </div>
  );
}

/** Attack types across, risk bands down. */
function ThreatMatrix({ stats }) {
  const matrix = stats?.by_type_risk || {};

  const columns = [...CLASSES, ...Object.keys(stats?.by_type || {}).filter((t) => !CLASSES.includes(t))];

  return (
    <section className="card matrix-card">
      <div className="card-head">
        <h2>Threat matrix</h2>
        <span className="muted small-text">alerts by attack type and risk band</span>
      </div>

      <div className="matrix" style={{ gridTemplateColumns: `110px repeat(${columns.length}, minmax(0, 1fr))` }}>
        <div />

        {columns.map((type) => (
          <div key={type} className="matrix-col" style={{ "--c": typeColor(type) }}>
            <span className="matrix-icon">
              <Icon name={type} size={22} />
            </span>
            <span>{type}</span>
            <b>{num(stats?.by_type?.[type] || 0)}</b>
          </div>
        ))}

        {BANDS.map((band) => (
          <Row key={band} band={band} columns={columns} matrix={matrix} />
        ))}
      </div>
    </section>
  );
}

function Row({ band, columns, matrix }) {
  return (
    <>
      <div className="matrix-band">
        <span className="dot" style={{ background: RISK_COLOR[band] }} />
        {band}
      </div>

      {columns.map((type) => {
        const n = matrix[type]?.[band] || 0;

        return (
          <div key={type} className={n ? "matrix-cell hit" : "matrix-cell"} style={{ "--c": RISK_COLOR[band] }}>
            {n ? num(n) : "·"}
          </div>
        );
      })}
    </>
  );
}

/** Share of alerts by attack type, with the total in the middle. */
function Ring({ byType }) {
  const data = Object.entries(byType || {})
    .map(([name, value]) => ({ name, value }))
    .sort((a, b) => b.value - a.value);

  const total = data.reduce((sum, d) => sum + d.value, 0);

  if (!total) return <div className="empty">No alerts yet.</div>;

  return (
    <div className="ring">
      <div className="ring-chart">
        <ResponsiveContainer width="100%" height={190}>
          <PieChart>
            <Pie
              data={data}
              dataKey="value"
              innerRadius={68}
              outerRadius={78}
              paddingAngle={2}
              cornerRadius={0}
              stroke="none"
              isAnimationActive={false}
            >
              {data.map((d) => (
                <Cell key={d.name} fill={typeColor(d.name)} />
              ))}
            </Pie>
            <Tooltip {...TOOLTIP} />
          </PieChart>
        </ResponsiveContainer>

        <div className="ring-total">
          <b>{num(total)}</b>
          <span>alerts</span>
        </div>
      </div>

      <ul className="legend">
        {data.map((d) => (
          <li key={d.name}>
            <span className="dot" style={{ background: typeColor(d.name) }} />
            {d.name}
            <b>{num(d.value)}</b>
            <em>{pct(d.value / total, 0)}</em>
          </li>
        ))}
      </ul>
    </div>
  );
}

/** Where alerts stand in handling: one capsule, split by status. */
function Handling({ byStatus }) {
  const order = ["new", "investigating", "resolved", "false_positive"];

  const total = order.reduce((sum, key) => sum + (byStatus?.[key] || 0), 0);

  if (!total) return <div className="empty">Nothing to handle yet.</div>;

  return (
    <div className="handling">
      <div className="capsule">
        {order
          .filter((key) => byStatus?.[key])
          .map((key) => (
            <span
              key={key}
              style={{ flexGrow: byStatus[key], background: STATUS_COLOR[key] }}
              title={`${STATUS_LABEL[key]}: ${byStatus[key]}`}
            />
          ))}
      </div>

      <div className="stages">
        {order.map((key) => (
          <div key={key} className="stage">
            <span className="dot" style={{ background: STATUS_COLOR[key] }} />
            <div>
              <b>{num(byStatus?.[key] || 0)}</b>
              <span>{STATUS_LABEL[key]}</span>
            </div>
            <em>{pct((byStatus?.[key] || 0) / total, 0)}</em>
          </div>
        ))}
      </div>
    </div>
  );
}

/** Flows to alerts to closed cases, as shrinking bars. */
function Funnel({ stats }) {
  if (!stats?.total) return <div className="empty">No traffic scored yet.</div>;

  const closed = (stats.by_status?.resolved || 0) + (stats.by_status?.false_positive || 0);

  const steps = [
    ["Flows scored", stats.total],
    ["Flagged as attacks", stats.alerts],
    ["Still open", open(stats)],
    ["Closed", closed]
  ];

  return (
    <div className="funnel">
      {steps.map(([label, value], i) => {
        const share = i > 0 && steps[i - 1][1] > 0 ? value / steps[i - 1][1] : null;

        return (
          <div key={label} className="funnel-step">
            <div className="funnel-label">
              <span>{label}</span>
              <b>{num(value)}</b>
              {share !== null && <em>{pct(share, share < 0.01 ? 2 : 1)} of previous</em>}
            </div>

            <div className="funnel-bar">
              <span style={{ width: `${Math.max(2, Math.sqrt(value / stats.total) * 100)}%` }} />
            </div>
          </div>
        );
      })}
    </div>
  );
}

export default function Overview({ live, stats, source, onOpenAlerts, onOpenDrift, browserAlerts, onBrowserAlerts }) {
  return (
    <div className="overview">
      <Hero stats={stats} onOpenAlerts={onOpenAlerts} />

      <ThreatMatrix stats={stats} />

      <div className="row two">
        <section className="card">
          <div className="card-head">
            <h2>Traffic and alerts</h2>
            <span className="muted small-text">per second</span>
          </div>
          <Timeline ticks={live.ticks} source={source} />
        </section>

        <section className="card">
          <div className="card-head">
            <h2>Attack mix</h2>
          </div>
          <Ring byType={stats?.by_type} />
        </section>
      </div>

      <div className="row two">
        <section className="card">
          <div className="card-head">
            <h2>Alert handling</h2>
          </div>
          <Handling byStatus={stats?.by_status} />
        </section>

        <section className="card">
          <div className="card-head">
            <h2>Detection funnel</h2>
          </div>
          <Funnel stats={stats} />
        </section>
      </div>

      <div className="row three">
        <SourcesCard revision={live.revision} />
        <DriftCard drift={live.drift} source={source} onOpenPage={onOpenDrift} />
        <NotificationsCard browserAlerts={browserAlerts} onBrowserAlerts={onBrowserAlerts} />
      </div>
    </div>
  );
}
