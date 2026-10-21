import { useEffect, useState } from "react";

import { getJSON, getToken, send, unauthorized } from "../api.js";
import { apiUrl } from "../config.js";

const duration = (seconds) => {
  const d = Math.floor(seconds / 86400);
  const h = Math.floor((seconds % 86400) / 3600);
  const m = Math.floor((seconds % 3600) / 60);

  return d ? `${d}d ${h}h` : h ? `${h}h ${m}m` : m ? `${m}m` : `${seconds}s`;
};

const megabytes = (bytes) => `${(bytes / 1e6).toFixed(1)} MB`;

export default function ServerPanel() {
  const [info, setInfo] = useState(null);
  const [error, setError] = useState("");
  const [restarting, setRestarting] = useState(false);
  const [busy, setBusy] = useState(false);

  const load = () =>
    getJSON("/api/server")
      .then((data) => {
        setInfo(data);
        return data;
      })
      .catch(() => null);

  useEffect(() => {
    load();

    const timer = setInterval(load, 15000);

    return () => clearInterval(timer);
  }, []);

  const restart = async () => {
    if (!window.confirm("Restart the server? Captures pause for a few seconds and the page reloads.")) return;

    setError("");

    const before = info.pid;

    try {
      await send("/api/server/restart", "POST");
    } catch (e) {
      setError(e.message);
      return;
    }

    setRestarting(true);

    // wait for a different process to answer, then reload the page
    const started = Date.now();

    const wait = async () => {
      const now = await load();

      if (now && now.pid !== before) return location.reload();

      if (Date.now() - started > 120000) {
        setRestarting(false);
        setError("The server did not come back within two minutes. Check logs/server.log.");
        return;
      }

      setTimeout(wait, 1500);
    };

    setTimeout(wait, 2500);
  };

  const autostart = async (enabled) => {
    setBusy(true);
    setError("");

    try {
      setInfo(await send("/api/server/autostart", "POST", { enabled }));
    } catch (e) {
      setError(e.message);
    }

    setBusy(false);
  };

  const backup = async () => {
    setError("");

    const token = getToken();

    const response = await fetch(apiUrl("/api/backup"), {
      headers: token ? { Authorization: `Bearer ${token}` } : {}
    });

    if (response.status === 401) return unauthorized();

    if (!response.ok) return setError(`Backup failed (${response.status}).`);

    const name =
      /filename="?([^"]+)"?/.exec(response.headers.get("content-disposition") || "")?.[1] ||
      "ids-backup.db";

    const url = URL.createObjectURL(await response.blob());

    const link = document.createElement("a");

    link.href = url;
    link.download = name;
    link.click();

    URL.revokeObjectURL(url);
  };

  if (!info) return null;

  return (
    <div className="card">
      <div className="card-head">
        <h2>Server</h2>
        <button className="btn small danger" disabled={restarting} onClick={restart}>
          {restarting ? "Restarting…" : "Restart server"}
        </button>
      </div>

      {restarting && (
        <div className="small-text muted">
          The server is restarting. This page reloads when it is back.
        </div>
      )}

      <table className="kv">
        <tbody>
          <tr>
            <td>Running for</td>
            <td className="r">{duration(info.uptime_seconds)}</td>
          </tr>
          <tr>
            <td>Process</td>
            <td className="r mono">{info.pid}</td>
          </tr>
          <tr>
            <td>System</td>
            <td className="r">
              {info.platform} · Python {info.python}
            </td>
          </tr>
          <tr>
            <td>Database</td>
            <td className="r mono">{megabytes(info.database_bytes)}</td>
          </tr>
        </tbody>
      </table>

      <div className="muted small-text path">{info.database}</div>

      <label className="check">
        <input
          type="checkbox"
          checked={info.autostart.enabled}
          disabled={busy || !info.autostart.supported}
          onChange={(e) => autostart(e.target.checked)}
        />
        Start the server when I sign in to this computer
      </label>

      <div className="muted small-text">
        {info.autostart.supported
          ? "Per-user, no administrator rights needed. For a service that starts at boot, see the deploy/ folder."
          : "Not available on this platform. See the deploy/ folder."}
      </div>

      <div className="capture-actions">
        <button className="btn small" onClick={backup}>
          Download backup
        </button>
      </div>

      <div className="muted small-text">
        The backup holds alerts, accounts and settings. Saved webhook URLs and passwords are
        encrypted with the key file next to the database (<code>.key</code>); keep that file
        too, or they cannot be read back.
      </div>

      {error && <div className="error">{error}</div>}
    </div>
  );
}
