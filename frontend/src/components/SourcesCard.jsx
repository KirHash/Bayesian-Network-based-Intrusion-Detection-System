import { useState } from "react";

import { getJSON } from "../api.js";
import { useRefresh } from "../useLive.js";
import { useAuth } from "../auth.js";
import { SOURCE_LABEL } from "../theme.js";

const HOW = {
  capture: "the Capture panel",
  api: "the API ingest panel",
  replay: "Start demo (top right)"
};

function ago(seconds) {
  if (seconds === null) return "never";
  if (seconds < 5) return "just now";
  if (seconds < 90) return `${seconds}s ago`;
  if (seconds < 5400) return `${Math.round(seconds / 60)} min ago`;
  return `${Math.round(seconds / 3600)} h ago`;
}

/** Whether each traffic source is actually delivering flows. */
export default function SourcesCard({ revision }) {
  const { isAdmin } = useAuth();
  const [sources, setSources] = useState(null);

  useRefresh(
    () =>
      getJSON("/api/sources")
        .then(setSources)
        .catch(() => {}),
    [],
    revision,
    2000
  );

  return (
    <div className="card">
      <div className="card-head">
        <h2>Sources</h2>
      </div>

      {!sources && <div className="empty small">Loading…</div>}

      {sources &&
        Object.entries(sources).map(([name, s]) => {
          const live = s.seconds_since_last !== null && s.seconds_since_last < 30;

          return (
            <div key={name} className="source">
              <div className="source-head">
                <span>
                  <span
                    className="dot"
                    style={{
                      background: live
                        ? "var(--good)"
                        : s.flows
                          ? "#f7d154"
                          : "var(--muted)"
                    }}
                  />{" "}
                  {SOURCE_LABEL[name]}
                </span>
                <span className="muted">
                  {s.flows.toLocaleString()} flows · {s.alerts.toLocaleString()}{" "}
                  alerts
                </span>
              </div>

              <div className="muted small-text">
                {s.flows === 0 && s.seconds_since_last === null ? (
                  <>
                    Nothing received yet.{isAdmin && <> Use {HOW[name]}.</>}
                  </>
                ) : (
                  <>last flow {ago(s.seconds_since_last)}</>
                )}
              </div>
            </div>
          );
        })}
    </div>
  );
}
