import { useState } from "react";

import { SOURCE_LABEL } from "../theme.js";
import Icon from "./Icons.jsx";

const RATES = [10, 50, 200, 1000];

const TITLES = {
  overview: "Overview",
  alerts: "Alerts",
  flows: "Recent flows",
  drift: "Traffic drift",
  account: "Your account",
  operations: "Operations"
};

/** Page title, the source filter, demo controls and who is signed in. */
export default function Topbar({
  page,
  model,
  source,
  onSource,
  replay,
  onReplay,
  onReset,
  user,
  isAdmin,
  onSignOut
}) {
  const card = model?.card;
  const [busy, setBusy] = useState(false);
  const [problem, setProblem] = useState("");

  // starting the demo may load a large dataset: show that, and show failures
  const replaySettings = async (settings) => {
    setBusy(true);
    setProblem("");

    try {
      await onReplay(settings);
    } catch (e) {
      setProblem(e.message);
    }

    setBusy(false);
  };

  const facts =
    model?.trained === false
      ? "No model yet: train one under Operations"
      : model
      ? `Tree-augmented Bayesian network · ${model.features} features · ${model.classes.length} classes` +
        (card?.trained_at ? ` · trained ${card.trained_at.slice(0, 10)}` : "")
      : "Loading model…";

  const filtered = ["overview", "alerts", "flows", "drift"].includes(page);

  return (
    <div className="topbar">
      <div className="topbar-title">
        <h1>{TITLES[page]}</h1>
        <div className="sub">{facts}</div>
      </div>

      <div className="topbar-tools">
        {filtered && (
          <label className="chip-field">
            <span>Source</span>
            <select value={source} onChange={(e) => onSource(e.target.value)}>
              {Object.entries(SOURCE_LABEL).map(([value, label]) => (
                <option key={value} value={value}>
                  {label}
                </option>
              ))}
            </select>
          </label>
        )}

        {isAdmin && page === "overview" && (
          <div className="controls">
            <button
              className={replay.running ? "btn danger" : "btn primary"}
              disabled={busy}
              onClick={() => replaySettings({ running: !replay.running })}
              title={problem || "Replays held-out dataset flows as demo traffic"}
            >
              {busy ? "Loading demo data…" : replay.running ? "Stop demo" : "Start demo"}
            </button>

            <label className="chip-field">
              <span>Flows/s</span>
              <select
                value={replay.rate}
                onChange={(e) => replaySettings({ rate: Number(e.target.value) })}
              >
                {[...new Set([...RATES, replay.rate])]
                  .sort((a, b) => a - b)
                  .map((rate) => (
                    <option key={rate} value={rate}>
                      {rate}
                    </option>
                  ))}
              </select>
            </label>

            <button className="btn" onClick={onReset} title="Clears demo alerts only; real alerts are kept">
              Clear demo
            </button>
          </div>
        )}

        {problem && <span className="miss small-text header-problem">{problem}</span>}

        {user && (
          <span className="who" title={`signed in as ${user.name}`}>
            <span className="avatar">{user.name.slice(0, 1).toUpperCase()}</span>
            {user.name} <span className="muted">· {user.role}</span>
          </span>
        )}

        {onSignOut && (
          <button className="btn icon" onClick={onSignOut} title="Sign out">
            <Icon name="signout" size={16} />
          </button>
        )}
      </div>
    </div>
  );
}
