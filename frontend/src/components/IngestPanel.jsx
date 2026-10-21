import { useEffect, useState } from "react";

import { getJSON, send } from "../api.js";
import { API_BASE } from "../config.js";

const SOURCE_TEXT = {
  environment: "required (set by IDS_API_KEY on the server)",
  dashboard: "required (created here)"
};

function copy(text) {
  navigator.clipboard?.writeText(text).catch(() => {});
}

export default function IngestPanel({ revision }) {
  const [info, setInfo] = useState(null);
  const [newKey, setNewKey] = useState("");
  const [error, setError] = useState("");
  const [example, setExample] = useState(false);

  const load = () =>
    getJSON("/api/ingest")
      .then(setInfo)
      .catch(() => {});

  useEffect(() => {
    load();
  }, [revision]);

  const act = async (path, method, body) => {
    setError("");

    try {
      const result = await send(path, method, body);

      if (result.key) setNewKey(result.key);
      else setNewKey("");

      setInfo(result);
    } catch (e) {
      setError(e.message);
    }
  };

  const url = `${API_BASE || location.origin}/api/score`;

  const curl = [
    `curl -X POST "${url}"`,
    `  -H "Content-Type: application/json"`,
    info?.key_required ? `  -H "X-API-Key: <your key>"` : null,
    `  -d '[{"Destination Port": 443, "Flow Duration": 50000, ...}]'`
  ]
    .filter(Boolean)
    .join(" \\\n");

  if (!info) return null;

  return (
    <div className="card">
      <div className="card-head">
        <h2>API ingest</h2>
        <button
          className={info.enabled ? "btn small danger" : "btn small primary"}
          onClick={() => act("/api/ingest", "POST", { enabled: !info.enabled })}
        >
          {info.enabled ? "Switch off" : "Switch on"}
        </button>
      </div>

      <div className="small-text">
        {info.enabled ? (
          <span className="ok">Accepting flows</span>
        ) : (
          <span className="miss">Switched off: requests get a 503</span>
        )}
      </div>

      <div className="small-text">
        Endpoint: <code>POST {url}</code>{" "}
        <button className="link" onClick={() => copy(url)}>
          copy
        </button>
      </div>

      <div className="small-text">
        API key:{" "}
        {info.key_required ? (
          SOURCE_TEXT[info.key_source]
        ) : (
          <span className="miss">
            none. Anyone who can reach this server can send flows.
          </span>
        )}
      </div>

      {newKey && (
        <div className="newkey">
          <div className="muted small-text">
            Copy this key now. It is not shown again.
          </div>
          <code>{newKey}</code>{" "}
          <button className="link" onClick={() => copy(newKey)}>
            copy
          </button>
        </div>
      )}

      {info.key_source !== "environment" && (
        <div className="capture-actions">
          <button className="btn small" onClick={() => act("/api/ingest/key", "POST")}>
            {info.key_required ? "Rotate key" : "Create key"}
          </button>

          {info.key_required && (
            <button
              className="btn small"
              onClick={() => act("/api/ingest/key", "DELETE")}
            >
              Remove key
            </button>
          )}
        </div>
      )}

      {error && <div className="error">{error}</div>}

      <button className="link" onClick={() => setExample(!example)}>
        {example ? "Hide example" : "Show example"}
      </button>

      {example && <pre className="snippet">{curl}</pre>}
    </div>
  );
}
