import { useState } from "react";

import { download } from "../api.js";
import { PRESETS, deleteView, loadViews, sameFilters, saveView } from "../views.js";

/** Saved filters, and the table's rows as a CSV file. */
export default function AlertViews({ current, source, onApply }) {
  const [saved, setSaved] = useState(loadViews);
  const [error, setError] = useState("");

  const all = [...PRESETS.map((v) => ({ ...v, preset: true })), ...saved];

  const active = all.find((v) => sameFilters(v, current));

  const choose = (event) => {
    const picked = all.find((v) => v.name === event.target.value);

    if (picked) onApply(picked);
  };

  const save = () => {
    const name = window.prompt("Name this view:", "");

    if (name && name.trim()) setSaved(saveView({ ...current, name }));
  };

  const remove = () => setSaved(deleteView(active.name));

  const exportCsv = async () => {
    setError("");

    const params = new URLSearchParams({
      status: current.status,
      ...(current.risk !== "all" && { risk: current.risk }),
      ...(current.type !== "all" && { attack_type: current.type }),
      ...(source !== "all" && { source }),
      ...(current.query.trim() && { q: current.query.trim() })
    });

    try {
      await download(`/api/alerts/export?${params}`, "alerts.csv");
    } catch (e) {
      setError(e.message);
    }
  };

  return (
    <div className="views">
      <select value={active?.name || ""} onChange={choose} aria-label="Saved views">
        <option value="" disabled>
          Views…
        </option>

        <optgroup label="Ready-made">
          {PRESETS.map((v) => (
            <option key={v.name}>{v.name}</option>
          ))}
        </optgroup>

        {saved.length > 0 && (
          <optgroup label="Yours">
            {saved.map((v) => (
              <option key={v.name}>{v.name}</option>
            ))}
          </optgroup>
        )}
      </select>

      <button className="btn small" onClick={save} title="Remember the filters as they are now">
        Save view…
      </button>

      {active && !active.preset && (
        <button className="btn small" onClick={remove}>
          Delete “{active.name}”
        </button>
      )}

      <button className="btn small" onClick={exportCsv} title="Download the alerts these filters show as a CSV file">
        Export CSV
      </button>

      {error && <span className="miss small-text">{error}</span>}
    </div>
  );
}
