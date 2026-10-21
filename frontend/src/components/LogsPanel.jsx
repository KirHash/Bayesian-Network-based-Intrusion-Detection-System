import { useEffect, useRef, useState } from "react";

import { getJSON } from "../api.js";

const KEEP = 600;

const LEVEL_CLASS = {
  WARNING: "warn-text",
  ERROR: "miss",
  CRITICAL: "miss"
};

function ServerLog() {
  const [level, setLevel] = useState("INFO");
  const [lines, setLines] = useState([]);
  const [follow, setFollow] = useState(true);
  const last = useRef(0);
  const box = useRef(null);

  // a new level starts the view again
  useEffect(() => {
    setLines([]);
    last.current = 0;
  }, [level]);

  useEffect(() => {
    let stopped = false;

    const poll = async () => {
      try {
        const fresh = await getJSON(`/api/logs?level=${level}&after=${last.current}&limit=500`);

        if (!stopped && fresh.length) {
          last.current = fresh[fresh.length - 1].n;
          setLines((l) => [...l, ...fresh].slice(-KEEP));
        }
      } catch {
        /* try again */
      }
    };

    poll();

    const timer = setInterval(poll, 3000);

    return () => {
      stopped = true;
      clearInterval(timer);
    };
  }, [level]);

  useEffect(() => {
    if (follow && box.current) box.current.scrollTop = box.current.scrollHeight;
  }, [lines, follow]);

  return (
    <>
      <div className="filters">
        <select value={level} onChange={(e) => setLevel(e.target.value)}>
          <option value="INFO">Info and above</option>
          <option value="WARNING">Warnings and errors</option>
          <option value="ERROR">Errors only</option>
        </select>

        <label className="inline-check small-text">
          <input type="checkbox" checked={follow} onChange={(e) => setFollow(e.target.checked)} />
          follow
        </label>
      </div>

      <div className="logbox tall" ref={box}>
        {lines.map((l) => (
          <div key={l.n} className={LEVEL_CLASS[l.level] || ""}>
            <span className="muted">{l.time.slice(11)}</span> {l.level.padEnd(7)} {l.message}
          </div>
        ))}

        {!lines.length && <div className="muted">nothing logged at this level yet</div>}
      </div>
    </>
  );
}

function Activity({ revision }) {
  const [entries, setEntries] = useState([]);

  const load = () =>
    getJSON("/api/audit?limit=200")
      .then(setEntries)
      .catch(() => {});

  useEffect(() => {
    load();

    const timer = setInterval(load, 8000);

    return () => clearInterval(timer);
  }, [revision]);

  return (
    <div className="logbox tall">
      {entries.map((e) => (
        <div key={e.id} className={e.action.startsWith("denied") || e.action === "login failed" ? "warn-text" : ""}>
          <span className="muted">{e.time.replace("T", " ")}</span> <b>{e.actor}</b> {e.action}
          {e.detail ? <span className="muted"> · {e.detail}</span> : null}
        </div>
      ))}

      {!entries.length && <div className="muted">no activity recorded yet</div>}
    </div>
  );
}

export default function LogsPanel({ revision }) {
  const [tab, setTab] = useState("activity");

  return (
    <div className="card">
      <div className="card-head">
        <h2>Logs and activity</h2>

        <div className="tabs compact">
          <button className={tab === "activity" ? "tab active" : "tab"} onClick={() => setTab("activity")}>
            Who did what
          </button>
          <button className={tab === "log" ? "tab active" : "tab"} onClick={() => setTab("log")}>
            Server log
          </button>
        </div>
      </div>

      {tab === "activity" ? <Activity revision={revision} /> : <ServerLog />}
    </div>
  );
}
