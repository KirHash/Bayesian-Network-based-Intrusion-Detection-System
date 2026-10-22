import { Area, AreaChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";

const AXIS = { stroke: "#8a8c92", fontSize: 11 };

const TOOLTIP = {
  contentStyle: {
    background: "#212023",
    border: "1px solid #3a3a3e",
    borderRadius: 6,
    fontSize: 12
  },
  labelStyle: { color: "#bdbdc0" }
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
        <CartesianGrid stroke="#2b2b2b" vertical={false} />
        <XAxis dataKey="t" {...AXIS} minTickGap={40} />
        <YAxis {...AXIS} />
        <Tooltip {...TOOLTIP} />
        <Area
          type="linear"
          dataKey="benign"
          name="Benign"
          stackId="1"
          stroke="#f2f2f3"
          strokeWidth={1.5}
          fill="#f2f2f3"
          fillOpacity={0.08}
          isAnimationActive={false}
        />
        <Area
          type="linear"
          dataKey="alerts"
          name="Alerts"
          stackId="1"
          stroke="#e5566f"
          strokeWidth={1.5}
          fill="#e5566f"
          fillOpacity={0.35}
          isAnimationActive={false}
        />
      </AreaChart>
    </ResponsiveContainer>
  );
}
