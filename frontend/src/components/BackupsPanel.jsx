import { useCallback, useEffect, useRef, useState } from "react";

import { download, getJSON, send, upload } from "../api.js";

const size = (bytes) =>
  bytes >= 1048576 ? `${(bytes / 1048576).toFixed(1)} MB` : `${Math.max(1, Math.round(bytes / 1024))} KB`;

const accounts = (n) => `${n} account${n === 1 ? "" : "s"}`;

/** Backups and recovery: automatic daily copies, one-click copies, and putting one back. */
export default function BackupsPanel({ revision }) {
  const [data, setData] = useState(null);
  const [busy, setBusy] = useState("");
  const [asking, setAsking] = useState("");
  const [error, setError] = useState("");
  const [note, setNote] = useState("");
  const file = useRef(null);
  const reloading = useRef(null);

  const load = useCallback(async () => {
    try {
      setData(await getJSON("/api/backups"));
    } catch (e) {
      setError(e.message);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load, revision]);

  // leaving the page first cancels the scheduled reload
  useEffect(() => () => clearTimeout(reloading.current), []);

  // one place for the busy flag, the error and the follow-up
  const run = async (label, job, done) => {
    setBusy(label);
    setError("");
    setNote("");

    try {
      const result = await job();

      if (done) setNote(done(result));

      await load();

      return result;
    } catch (e) {
      setError(e.message);

      return null;
    } finally {
      setBusy("");
    }
  };

  const backUp = () =>
    run("make", () => send("/api/backups", "POST", {}), (row) => `Saved ${row.name} (${size(row.size)}).`);

  const restore = async (name) => {
    setAsking("");

    const result = await run(
      "restore:" + name,
      () => send(`/api/backups/${name}/restore`, "POST", {}),
      (r) =>
        `Restored ${r.restored}: ${r.alerts.toLocaleString()} alerts and ${accounts(r.users)}. ` +
        `The state it replaced is kept as ${r.safety}. Other people were signed out.`
    );

    // the screen was built from the old data: load it again from the restored database
    if (result) reloading.current = setTimeout(() => location.reload(), 2500);
  };

  const remove = (name) =>
    run("delete:" + name, () => send(`/api/backups/${name}`, "DELETE"), () => `Deleted ${name}.`);

  const choose = async (event) => {
    const picked = event.target.files?.[0];

    event.target.value = "";

    if (!picked) return;

    await run(
      "upload",
      () => upload("/api/backups/upload", picked),
      (r) =>
        `Checked and kept ${r.name}: ${r.alerts.toLocaleString()} alerts, ${accounts(r.users)}. ` +
        "Restore it from the list below when you are ready."
    );
  };

  if (!data) {
    return error ? (
      <div className="card">
        <h2>Backups and recovery</h2>
        <div className="error">{error}</div>
      </div>
    ) : null;
  }

  const newest = data.backups.find((b) => b.kind !== "before-restore");

  return (
    <div className="card">
      <div className="card-head">
        <h2>Backups and recovery</h2>

        <div className="card-actions">
          <button className="btn small" disabled={!!busy} onClick={() => file.current?.click()}>
            {busy === "upload" ? "Checking…" : "Upload a backup"}
          </button>

          <button className="btn small primary" disabled={!!busy} onClick={backUp}>
            {busy === "make" ? "Saving…" : "Back up now"}
          </button>
        </div>
      </div>

      <input
        ref={file}
        type="file"
        accept=".db,application/octet-stream"
        hidden
        onChange={choose}
        aria-label="Backup file"
      />

      <div className="muted small-text">
        {newest ? `Latest copy: ${newest.created}.` : "No copy yet."} A copy is made automatically every day and the
        newest {data.keep} are kept in <code>{data.folder}</code>.
      </div>

      {data.last_error && <div className="error">The last automatic backup failed: {data.last_error}</div>}

      {!data.backups.length ? (
        <div className="empty small">No backups yet. Press Back up now to make the first one.</div>
      ) : (
        <table className="mini" aria-label="Backups">
          <thead>
            <tr>
              <th>Copy</th>
              <th className="r">Size</th>
              <th />
            </tr>
          </thead>

          <tbody>
            {data.backups.map((b) => (
              <tr key={b.name}>
                <td>
                  {b.created}
                  <div className="muted small-text">{b.label}</div>
                </td>

                <td className="r">{size(b.size)}</td>

                <td className="r">
                  {asking === b.name ? (
                    <span className="row-actions">
                      <button className="btn small danger" disabled={!!busy} onClick={() => restore(b.name)}>
                        {busy === "restore:" + b.name ? "Restoring…" : "Yes, replace everything"}
                      </button>

                      <button className="btn small" onClick={() => setAsking("")}>
                        Cancel
                      </button>
                    </span>
                  ) : (
                    <span className="row-actions">
                      <button
                        className="btn small"
                        disabled={!!busy}
                        onClick={() => download(`/api/backups/${b.name}`, b.name).catch((e) => setError(e.message))}
                      >
                        Download
                      </button>

                      <button className="btn small" disabled={!!busy} onClick={() => setAsking(b.name)}>
                        Restore
                      </button>

                      <button
                        className="btn small"
                        disabled={!!busy}
                        onClick={() => remove(b.name)}
                        aria-label={`Delete ${b.name}`}
                      >
                        Delete
                      </button>
                    </span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      {asking && (
        <div className="warnbox" role="alert">
          Restoring replaces all alerts, accounts and settings with this copy. A copy of the current state is saved
          first, and everyone except you is signed out.
        </div>
      )}

      {note && <div className="note">{note}</div>}
      {error && <div className="error">{error}</div>}

      <div className="muted small-text">
        A backup holds alerts, accounts and settings, never logins. Saved passwords and webhook URLs are encrypted with
        the key file next to the database (<code>.key</code>): keep a copy of it somewhere else, because a restore on
        another machine cannot read them without it. Locked out completely? On the server, run{" "}
        <code style={{ whiteSpace: "nowrap" }}>python manage_users.py passwd NAME</code>.
      </div>
    </div>
  );
}
