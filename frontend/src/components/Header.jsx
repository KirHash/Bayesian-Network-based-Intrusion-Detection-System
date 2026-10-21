import { useState } from "react";

import { SOURCE_LABEL } from "../theme.js";

const RATES = [10, 50, 200, 1000];

export default function Header({
  model,
  connected,
  source,
  onSource,
  replay,
  onReplay,
  onReset,
  onSignOut,
  user,
  isAdmin,
  page = "monitor",
  onPage
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

  return (
    <header>
      <div>
        <h1>Bayesian IDS</h1>
        <div className="sub">
          {model?.trained === false
            ? "No model yet: train one under Operations"
            : model
            ? `Tree-augmented Bayesian network · ${model.features} features · ${model.classes.length} classes` +
              (card?.trained_at
                ? ` · trained ${card.trained_at.slice(0, 10)}`
                : "")
            : "Loading model…"}
        </div>
      </div>

      {isAdmin && onPage && (
        <nav className="nav">
          <button
            className={page === "monitor" ? "tab active" : "tab"}
            onClick={() => onPage("monitor")}
          >
            Monitor
          </button>
          <button
            className={page === "operations" ? "tab active" : "tab"}
            onClick={() => onPage("operations")}
          >
            Operations
          </button>
        </nav>
      )}

      <div className="header-right">
        {page === "monitor" && (
        <label className="field">
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

        {isAdmin && page === "monitor" && (
        <div className="controls">
          <button
            className={replay.running ? "btn danger" : "btn primary"}
            disabled={busy}
            onClick={() => replaySettings({ running: !replay.running })}
            title={problem || "Replays held-out dataset flows as demo traffic"}
          >
            {busy ? "Loading demo data…" : replay.running ? "Stop demo" : "Start demo"}
          </button>

          <label className="field">
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

          <button
            className="btn"
            onClick={onReset}
            title="Clears demo alerts only; real alerts are kept"
          >
            Clear demo
          </button>
        </div>
        )}

        {problem && <span className="miss small-text header-problem">{problem}</span>}

        {user && (
          <span className="who" title={`signed in as ${user.name}`}>
            {user.name} <span className="muted">· {user.role}</span>
          </span>
        )}

        {onSignOut && (
          <button className="btn small" onClick={onSignOut}>
            Sign out
          </button>
        )}

        <span className={`status ${connected ? "on" : "off"}`}>
          <span className="dot" />
          {connected ? "Live" : "Reconnecting…"}
        </span>
      </div>
    </header>
  );
}
