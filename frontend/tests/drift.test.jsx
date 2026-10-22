import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import DriftCard from "../src/components/DriftCard.jsx";
import DriftPage from "../src/components/DriftPage.jsx";
import { api } from "./helpers.js";

const STABLE = {
  status: "stable",
  flows: 5000,
  window: 5000,
  max_psi: 0.08,
  worst_feature: "Flow_Duration",
  anomaly_rate: 0.004,
  expected_anomaly_rate: 0.005,
  features: { Flow_Duration: 0.08, Destination_Port: 0.02, Packet_Length_Mean: 0.5 }
};

const DRIFT = { ...STABLE, status: "drift", max_psi: 0.91, anomaly_rate: 0.07 };

const HISTORY = {
  replay: [
    { at: 1, t: "10:00:00", status: "stable", max_psi: 0.1, anomaly_rate: 0.004 },
    { at: 2, t: "10:00:10", status: "warning", max_psi: 0.35, anomaly_rate: 0.01 },
    { at: 3, t: "10:00:20", status: "drift", max_psi: 0.9, anomaly_rate: 0.07 }
  ]
};

const mount = (drift, source = "all") => {
  api({ "GET /api/drift/history": HISTORY });

  return render(<DriftPage drift={drift} source={source} revision={0} />);
};

describe("the drift page", () => {
  it("explains what drift is before there is anything to show", () => {
    mount({});

    expect(screen.getByText("What drift means")).toBeTruthy();
    expect(screen.getByText(/Nothing to compare yet/)).toBeTruthy();
  });

  it("tells a stable source in plain words and ranks its features", async () => {
    const { container } = mount({ replay: STABLE });

    expect(await screen.findByText("stable")).toBeTruthy();
    expect(screen.getByText(/Nothing to do/)).toBeTruthy();
    expect(screen.getByText("Demo replay")).toBeTruthy();

    // numbers, in words
    // the worst feature is named in the summary and again in the ranked list
    expect(screen.getAllByText("Flow Duration")).toHaveLength(2);
    expect(screen.getByText("PSI 0.08")).toBeTruthy();
    expect(screen.getByText("0.40%")).toBeTruthy();
    expect(screen.getByText("normal is 0.5%")).toBeTruthy();
    expect(screen.getByText("5,000")).toBeTruthy();

    // every feature, most changed first
    const names = [...container.querySelectorAll(".drift-features .bar-row > span:first-child")].map((s) => s.textContent);

    expect(names).toEqual(["Packet Length Mean", "Flow Duration", "Destination Port"]);
  });

  it("says what to do about real drift", async () => {
    mount({ replay: DRIFT });

    expect(await screen.findByText("drift")).toBeTruthy();
    expect(screen.getByText(/Retrain with data from this network/)).toBeTruthy();
    expect(screen.getByText("PSI 0.91")).toBeTruthy();
    expect(screen.getByText("7.00%")).toBeTruthy();
  });

  it("copes with a source that is still warming up", () => {
    mount({ api: { status: "warming up", flows: 12, window: 5000, anomaly_rate: 0, expected_anomaly_rate: 0.005, features: {} } });

    expect(screen.getByText(/Not enough normal flows/)).toBeTruthy();
    expect(screen.getByText("not yet measured")).toBeTruthy();
    expect(document.querySelector(".drift-features")).toBeNull();
  });

  it("shows only the chosen source", () => {
    mount({ replay: STABLE, api: DRIFT }, "api");

    expect(screen.getByText("API")).toBeTruthy();
    expect(screen.queryByText("Demo replay")).toBeNull();
  });

  it("asks the server for the history of the chosen source", async () => {
    const { calls } = api({ "GET /api/drift/history": HISTORY });

    render(<DriftPage drift={{ replay: STABLE }} source="replay" revision={0} />);

    await screen.findByText("stable");

    expect(calls.some((c) => c.path === "/api/drift/history")).toBe(true);
  });
});

describe("the drift card on the overview", () => {
  it("links to the page", async () => {
    const open = vi.fn();

    render(<DriftCard drift={{ replay: STABLE }} source="all" onOpenPage={open} />);

    await userEvent.click(screen.getByRole("button", { name: "Details" }));

    expect(open).toHaveBeenCalledOnce();
  });

  it("has no link when there is nowhere to go", () => {
    render(<DriftCard drift={{ replay: STABLE }} source="all" />);

    expect(screen.queryByRole("button", { name: "Details" })).toBeNull();
  });
});
