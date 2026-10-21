import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis
} from "recharts";

import { RISK_COLOR, RISK_ORDER, typeColor } from "../theme.js";

const AXIS = { stroke: "#5b6577", fontSize: 11 };

const TOOLTIP = {
  contentStyle: {
    background: "#161b26",
    border: "1px solid #2a3142",
    borderRadius: 8,
    fontSize: 12
  },
  labelStyle: { color: "#aab3c5" }
};

function Empty({ children = "No data yet." }) {
  return <div className="empty">{children}</div>;
}

/** Per-second ticks for the chosen source; "all" sums the sources. */
function mergeTicks(ticks, source) {
  const merged = new Map();

  for (const tick of ticks) {
    if (source !== "all" && tick.source !== source) continue;

    const slot = merged.get(tick.t) || { t: tick.t, flows: 0, alerts: 0 };

    slot.flows += tick.flows;
    slot.alerts += tick.alerts;

    merged.set(tick.t, slot);
  }

  return [...merged.values()].slice(-120).map((tick) => ({
    t: tick.t,
    alerts: tick.alerts,
    benign: tick.flows - tick.alerts
  }));
}

export function Timeline({ ticks, source }) {
  const data = mergeTicks(ticks, source);

  if (!data.length) return <Empty>No traffic yet. Start the demo or a capture.</Empty>;

  return (
    <ResponsiveContainer width="100%" height={220}>
      <AreaChart data={data} margin={{ left: -12, right: 8, top: 8 }}>
        <CartesianGrid stroke="#222a3a" vertical={false} />
        <XAxis dataKey="t" {...AXIS} minTickGap={40} />
        <YAxis {...AXIS} />
        <Tooltip {...TOOLTIP} />
        <Area
          type="monotone"
          dataKey="benign"
          name="Benign"
          stackId="1"
          stroke="#4cc38a"
          fill="#4cc38a"
          fillOpacity={0.18}
          isAnimationActive={false}
        />
        <Area
          type="monotone"
          dataKey="alerts"
          name="Alerts"
          stackId="1"
          stroke="#ff5370"
          fill="#ff5370"
          fillOpacity={0.45}
          isAnimationActive={false}
        />
      </AreaChart>
    </ResponsiveContainer>
  );
}

export function TypeDonut({ byType }) {
  const data = Object.entries(byType || {})
    .map(([name, value]) => ({ name, value }))
    .sort((a, b) => b.value - a.value);

  if (!data.length) return <Empty />;

  return (
    <div className="donut">
      <ResponsiveContainer width="100%" height={170}>
        <PieChart>
          <Pie
            data={data}
            dataKey="value"
            innerRadius={46}
            outerRadius={72}
            paddingAngle={2}
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

      <ul className="legend">
        {data.map((d) => (
          <li key={d.name}>
            <span className="dot" style={{ background: typeColor(d.name) }} />
            {d.name}
            <b>{d.value.toLocaleString()}</b>
          </li>
        ))}
      </ul>
    </div>
  );
}

export function RiskBars({ byRisk }) {
  const data = RISK_ORDER.filter((level) => level !== "Low").map((level) => ({
    level,
    count: (byRisk || {})[level] || 0
  }));

  if (!data.some((d) => d.count)) return <Empty />;

  return (
    <ResponsiveContainer width="100%" height={200}>
      <BarChart data={data} margin={{ left: -12, right: 8, top: 8 }}>
        <CartesianGrid stroke="#222a3a" vertical={false} />
        <XAxis dataKey="level" {...AXIS} />
        <YAxis {...AXIS} />
        <Tooltip {...TOOLTIP} cursor={{ fill: "#ffffff08" }} />
        <Bar
          dataKey="count"
          name="Alerts"
          radius={[4, 4, 0, 0]}
          isAnimationActive={false}
        >
          {data.map((d) => (
            <Cell key={d.level} fill={RISK_COLOR[d.level]} />
          ))}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  );
}
