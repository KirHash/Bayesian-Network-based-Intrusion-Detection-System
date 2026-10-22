import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import Overview from "../src/components/Overview.jsx";
import { api } from "./helpers.js";

const LIVE = {
  ticks: [],
  drift: {},
  replay: { running: false, rate: 50 },
  revision: 0,
  capture: null
};

const STATS = {
  total: 4400,
  alerts: 910,
  by_type: { DDoS: 401, PortScan: 470, Bot: 10, Anomaly: 21, "DoS Hulk": 8 },
  by_risk: { Critical: 720, High: 150, Medium: 40 },
  by_status: { new: 893, investigating: 6, resolved: 8, false_positive: 3 },
  by_type_risk: {
    DDoS: { Critical: 264, High: 130, Medium: 7 },
    PortScan: { Critical: 455, High: 15 },
    "DoS Hulk": { High: 8 }
  },
  labelled: 4400,
  precision: 0.969,
  recall: 0.992,
  false_alarm_rate: 0.008
};

function mount(stats, extra = {}) {
  api({
    "GET /api/sources": { capture: { flows: 0, alerts: 0, last: null }, api: { flows: 0, alerts: 0, last: null }, replay: { flows: 0, alerts: 0, last: null } },
    "GET /api/notifications": { channels: [], recent: [] }
  });

  return render(
    <Overview
      live={LIVE}
      stats={stats}
      source="all"
      onOpenAlerts={extra.onOpenAlerts || (() => {})}
      browserAlerts={false}
      onBrowserAlerts={() => {}}
    />
  );
}

describe("the overview", () => {
  it("leads with what needs attention", () => {
    mount(STATS);

    // open = new + investigating
    expect(screen.getByText("899 alerts need attention")).toBeTruthy();
    expect(screen.getByText(/720 of them rated Critical/)).toBeTruthy();
    expect(screen.getByText(/4,400 flows scored, 910 flagged \(20.68%\)/)).toBeTruthy();
  });

  it("offers the way to the alerts only when something is waiting", async () => {
    const onOpenAlerts = vi.fn();

    mount(STATS, { onOpenAlerts });

    await userEvent.click(screen.getByRole("button", { name: "Review alerts" }));

    expect(onOpenAlerts).toHaveBeenCalledOnce();
  });

  it("says so when everything is handled", () => {
    mount({ ...STATS, by_status: { resolved: 910 } });

    expect(screen.getByText("All quiet. Nothing is waiting for you.")).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Review alerts" })).toBeNull();
  });

  it("waits quietly before any traffic", () => {
    mount({ total: 0, alerts: 0, by_type: {}, by_risk: {}, by_status: {}, by_type_risk: {} });

    expect(screen.getByText("Waiting for traffic")).toBeTruthy();
    expect(screen.getByText(/Start the demo, a live capture/)).toBeTruthy();
  });

  it("shows the accuracy numbers it was given", () => {
    mount(STATS);

    expect(screen.getByText("96.9%")).toBeTruthy();
    expect(screen.getByText("99.2%")).toBeTruthy();
    expect(screen.getByText("4,400 labelled")).toBeTruthy();
  });

  it("lays alerts out by attack type and risk band, including types it was not told about", () => {
    const { container } = mount(STATS);

    const columns = [...container.querySelectorAll(".matrix-col")].map((c) => c.textContent);

    // the five usual types, then one that only appears because it has alerts
    expect(columns.map((c) => c.replace(/\d[\d,]*$/, ""))).toEqual([
      "DDoS", "PortScan", "Web Attack", "Bot", "Anomaly", "DoS Hulk"
    ]);

    const cells = [...container.querySelectorAll(".matrix-cell")].map((c) => c.textContent);

    // rows are Critical, High, Medium across the six columns
    expect(cells.slice(0, 6)).toEqual(["264", "455", "·", "·", "·", "·"]);
    expect(cells.slice(6, 12)).toEqual(["130", "15", "·", "·", "·", "8"]);
    expect(cells.slice(12, 18)).toEqual(["7", "·", "·", "·", "·", "·"]);
  });

  it("splits the handling of alerts by status and shrinks the funnel", () => {
    const { container } = mount(STATS);

    const stages = [...container.querySelectorAll(".stage")].map((s) => s.textContent);

    expect(stages[0]).toContain("893");
    expect(stages[2]).toContain("8");

    const funnel = [...container.querySelectorAll(".funnel-step")].map((s) => s.textContent);

    expect(funnel[0]).toContain("Flows scored4,400");
    expect(funnel[1]).toContain("Flagged as attacks910");
    expect(funnel[2]).toContain("Still open899");
    expect(funnel[3]).toContain("Closed11");
  });
});
