import { useEffect, useState } from "react";

import { getJSON, send } from "../api.js";

const MODES = {
  interface: "Network interface (live)",
  pcap: "PCAP file",
  csv: "Flow CSV (follow)"
};

const STATE_COLOR = {
  running: "#4cc38a",
  starting: "#f7d154",
  retrying: "#ff9f43",
  finished: "#4dabf7",
  error: "#ff5370",
  stopped: "#8b95a7"
};

const STATE_LABEL = {
  running: "Running",
  starting: "Starting…",
  retrying: "Retrying",
  finished: "Finished",
  error: "Error",
  stopped: "Stopped"
};

/** Hints for the failures people actually hit. */
function hint(message) {
  if (!message) return null;

  if (/npcap|wpcap|libpcap|winpcap/i.test(message))
    return "Packet capture needs Npcap (Windows) or libpcap (Linux/macOS) installed.";

  if (/permission|not permitted|access is denied|administrator|root/i.test(message))
    return "Capturing usually needs administrator / root rights. Run the server as an administrator, or on Linux grant it CAP_NET_RAW.";

  if (/not found|unknown interface/i.test(message))
    return "That interface no longer exists. Pick another one and refresh the list.";

  if (/missing flow columns/i.test(message))
    return "The CSV does not have the columns the model needs (CICFlowMeter naming).";

  return null;
}

const label = (iface) =>
  iface.ip ? `${iface.name} (${iface.ip})` : iface.name;

export default function CapturePanel({ status }) {
  const [options, setOptions] = useState(null);
  const [mode, setMode] = useState("interface");
  const [target, setTarget] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const loadOptions = () =>
    getJSON("/api/capture/options")
      .then((data) => {
        setOptions(data);
        return data;
      })
      .catch(() => {});

  useEffect(() => {
    loadOptions().then((data) => {
      if (!data) return;

      // start from the saved choice, else the first usable interface
      if (data.saved) {
        setMode(data.saved.mode);
        setTarget(data.saved.target);
      } else {
        const first = data.interfaces.find((i) => i.usable) || data.interfaces[0];
        if (first) setTarget(first.name);
      }
    });
  }, []);

  const choices =
    mode === "interface"
      ? (options?.interfaces || []).map((i) => ({
          value: i.name,
          text: label(i),
          dim: !i.usable
        }))
      : (options?.files?.[mode] || []).map((f) => ({ value: f, text: f }));

  const changeMode = (next) => {
    setMode(next);

    const list =
      next === "interface"
        ? (options?.interfaces || []).filter((i) => i.usable).map((i) => i.name)
        : options?.files?.[next] || [];

    setTarget(list[0] || "");
  };

  const active = ["running", "starting", "retrying"].includes(status?.state);

  const act = async (path, body) => {
    setBusy(true);
    setError("");

    try {
      await send(path, "POST", body);
    } catch (e) {
      setError(e.message);
    }

    setBusy(false);
  };

  const state = status?.state || "stopped";

  return (
    <div className="card">
      <div className="card-head">
        <h2>Capture</h2>
        <span
          className="badge"
          style={{
            color: STATE_COLOR[state],
            borderColor: STATE_COLOR[state] + "55",
            background: STATE_COLOR[state] + "18"
          }}
        >
          {STATE_LABEL[state]}
          {state === "retrying" && status.retry_in ? ` in ${status.retry_in}s` : ""}
        </span>
      </div>

      {active ? (
        <div className="small-text">
          {MODES[status.mode]}: <b>{status.target}</b>
        </div>
      ) : (
        <>
          <label className="stack">
            <span>Input</span>
            <select value={mode} onChange={(e) => changeMode(e.target.value)}>
              {Object.entries(MODES).map(([value, text]) => (
                <option key={value} value={value}>
                  {text}
                </option>
              ))}
            </select>
          </label>

          <label className="stack">
            <span>
              {mode === "interface" ? "Interface" : "File"}{" "}
              <button className="link" onClick={loadOptions}>
                refresh
              </button>
            </span>
            <select value={target} onChange={(e) => setTarget(e.target.value)}>
              {!choices.length && <option value="">None available</option>}
              {choices.map((c) => (
                <option key={c.value} value={c.value}>
                  {c.text}
                </option>
              ))}
            </select>
          </label>

          {mode !== "interface" && options && (
            <div className="muted small-text">
              Put files in <code>{options.data_dir}</code>
            </div>
          )}
        </>
      )}

      <div className="capture-actions">
        {active ? (
          <button
            className="btn danger"
            disabled={busy}
            onClick={() => act("/api/capture/stop")}
          >
            Stop capture
          </button>
        ) : (
          <button
            className="btn primary"
            disabled={busy || !target}
            onClick={() => act("/api/capture/start", { mode, target })}
          >
            Start capture
          </button>
        )}
      </div>

      {(state !== "stopped" || status?.packets > 0) && (
        <div className="muted small-text">
          {mode === "csv" || status?.mode === "csv"
            ? ""
            : `${status.packets.toLocaleString()} packets · `}
          {status.flows.toLocaleString()} flows · {status.alerts.toLocaleString()}{" "}
          alerts
          {status.started_at ? ` · since ${status.started_at.slice(11)}` : ""}
        </div>
      )}

      {mode === "interface" && options?.environment?.problems?.map((problem) => (
        <div className="error" key={problem}>
          {problem}
        </div>
      ))}

      {mode === "interface" &&
        options?.environment?.hints?.map((text) => (
          <div className="muted small-text" key={text}>
            {text}
          </div>
        ))}

      {(error || status?.error) && (
        <div className="error">
          {error || status.error}
          {hint(error || status.error) && (
            <div className="hint">{hint(error || status.error)}</div>
          )}
        </div>
      )}

      <label className="check">
        <input
          type="checkbox"
          checked={!!status?.autostart}
          onChange={(e) =>
            act("/api/capture/autostart", { enabled: e.target.checked })
          }
        />
        Start automatically when the server starts
      </label>
    </div>
  );
}
