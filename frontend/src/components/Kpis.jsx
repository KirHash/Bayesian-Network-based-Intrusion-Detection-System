import { num, pct } from "../theme.js";

function Kpi({ label, value, hint, tone }) {
  return (
    <div className="card kpi">
      <div className="kpi-label">{label}</div>
      <div className={`kpi-value ${tone || ""}`}>{value}</div>
      <div className="kpi-hint">{hint}</div>
    </div>
  );
}

export default function Kpis({ stats }) {
  if (!stats) return <div className="kpis" />;

  const open =
    (stats.by_status?.new || 0) + (stats.by_status?.investigating || 0);

  const rate = stats.total ? stats.alerts / stats.total : null;

  return (
    <div className="kpis">
      <Kpi label="Flows scored" value={num(stats.total)} hint="persisted" />
      <Kpi
        label="Alerts"
        value={num(stats.alerts)}
        hint={`${pct(rate, 2)} of flows`}
      />
      <Kpi
        label="Open alerts"
        value={num(open)}
        hint={`${num(stats.by_status?.new || 0)} new`}
        tone="alert"
      />
      <Kpi
        label="Precision"
        value={pct(stats.precision)}
        hint={
          stats.labelled
            ? `${num(stats.labelled)} labelled flows`
            : "needs labelled flows"
        }
      />
      <Kpi
        label="Recall"
        value={pct(stats.recall)}
        hint={`false alarms ${pct(stats.false_alarm_rate, 2)}`}
      />
    </div>
  );
}
