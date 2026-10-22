import { useEffect, useRef, useState } from "react";

import { getJSON, send } from "../api.js";
import { pct } from "../theme.js";

const ACTIONS = [
  ["train", "Retrain", "Learn again from the dataset in the Data section"],
  ["evaluate", "Evaluate", "Score the held-out 30% and print accuracy"],
  ["compare", "Compare baselines", "Train random forest etc. on the same data (several minutes)"]
];

const STATE_COLOR = {
  running: "#f7d154",
  succeeded: "#4cc38a",
  failed: "#ff5370",
  cancelled: "#8b95a7"
};

/** Output of one job, followed live while it runs. */
function JobLog({ job, onDone }) {
  const [lines, setLines] = useState([]);
  const [state, setState] = useState(job.state);
  const box = useRef(null);
  const next = useRef(0);

  useEffect(() => {
    setLines([]);
    setState(job.state);
    next.current = 0;

    let stopped = false;

    const poll = async () => {
      try {
        const data = await getJSON(`/api/jobs/${job.id}?after=${next.current}`);

        if (stopped) return;

        if (data.output.length) setLines((l) => [...l, ...data.output]);

        next.current = data.from + data.output.length;

        setState(data.state);

        if (data.state !== "running") {
          onDone?.(data);
          return;
        }
      } catch {
        /* retry */
      }

      setTimeout(poll, 1000);
    };

    poll();

    return () => {
      stopped = true;
    };
  }, [job.id]);

  useEffect(() => {
    if (box.current) box.current.scrollTop = box.current.scrollHeight;
  }, [lines]);

  return (
    <div>
      <div className="small-text">
        <span style={{ color: STATE_COLOR[state] }}>{state}</span>
        <span className="muted">
          {" "}
          · {job.title} · started by {job.actor} · {job.started_at.slice(11)}
        </span>
      </div>

      <pre className="logbox" ref={box}>
        {lines.join("\n") || "waiting for output…"}
      </pre>
    </div>
  );
}

export default function ModelPanel({ revision, liveJob }) {
  const [model, setModel] = useState(null);
  const [jobs, setJobs] = useState([]);
  const [shown, setShown] = useState(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const load = async () => {
    try {
      setModel(await getJSON("/api/model"));

      const list = await getJSON("/api/jobs");

      setJobs(list.jobs);

      // follow a running job, else the latest one
      setShown((current) => {
        if (current && list.jobs.some((j) => j.id === current.id && j.state === "running")) {
          return current;
        }

        return list.jobs.find((j) => j.state === "running") || current || list.jobs[0] || null;
      });
    } catch {
      /* the page shows what it has */
    }
  };

  useEffect(() => {
    load();
  }, [revision]);

  const running = jobs.find((j) => j.state === "running");

  const act = async (fn) => {
    setBusy(true);
    setError("");

    try {
      await fn();
      await load();
    } catch (e) {
      setError(e.message);
    }

    setBusy(false);
  };

  const start = (kind) =>
    act(async () => {
      const job = await send("/api/jobs", "POST", { kind });
      setShown(job);
    });

  const card = model?.card || {};

  const test = card.test;

  const forest = model?.forest;

  const plain = card.test_without_forest;

  const setForest = (confirm) =>
    act(async () => {
      await send("/api/model/forest", "PUT", { confirm });
    });

  return (
    <div className="card">
      <div className="card-head">
        <h2>Model</h2>
        {model?.trained !== false && model && (
          <span className="muted small-text">
            {model.classes.length} classes · {model.features} features
          </span>
        )}
      </div>

      {model?.trained === false && (
        <div className="warnbox">
          <b>No model has been trained yet.</b> Without one nothing can be scored.{" "}
          {model.dataset_files
            ? "Press Retrain to learn from the dataset below."
            : "Upload the CIC-IDS-2017 CSVs in the Data section, then press Retrain."}
        </div>
      )}

      {model?.trained !== false && model && (
        <div className="small-text">
          Trained {card.trained_at ? card.trained_at.replace("T", " ") : "(unknown)"} on{" "}
          {card.training_rows?.toLocaleString() ?? "?"} flows
          {card.classes && (
            <div className="chips">
              {Object.entries(card.classes).map(([name, n]) => (
                <span className="chip" key={name}>
                  {name} <b>{n.toLocaleString()}</b>
                </span>
              ))}
            </div>
          )}
        </div>
      )}

      {model?.trained === false ? null : test ? (
        <table className="mini">
          <thead>
            <tr>
              <th>Held-out test ({test.rows.toLocaleString()} flows)</th>
              <th className="r">Flagged</th>
              <th className="r">Typed right</th>
            </tr>
          </thead>
          <tbody>
            {Object.entries(test.per_label).map(([label, r]) => (
              <tr key={label}>
                <td>{label}</td>
                <td className="r mono">{pct(r.flagged)}</td>
                <td className="r mono">{pct(r.typed_correctly)}</td>
              </tr>
            ))}
            <tr className="total">
              <td>Overall</td>
              <td className="r mono" colSpan={2}>
                precision {pct(test.precision)} · recall {pct(test.recall)} · F1 {test.f1}
              </td>
            </tr>
          </tbody>
        </table>
      ) : (
        model && (
          <div className="muted small-text">
            No held-out results are stored with this model. Retrain to get them.
          </div>
        )
      )}

      {model?.library_mismatch && Object.keys(model.library_mismatch).length > 0 && (
        <div className="warnbox">
          <b>This model was trained with other library versions than the ones installed</b>:{" "}
          {Object.entries(model.library_mismatch)
            .map(([name, v]) => `${name} ${v.trained} → ${v.installed}`)
            .join(", ")}
          . It still loads, but results can differ and a newer library may stop reading it. Retrain to be safe.
        </div>
      )}

      {forest?.available && (
        <div className="forest-box">
          <label className="check">
            <input
              type="checkbox"
              checked={forest.confirm}
              disabled={busy}
              onChange={(e) => setForest(e.target.checked)}
            />
            <span>
              <b>Second opinion from a random forest</b>
              <span className="muted small-text">
                {" "}
                Alerts from the classifier are kept only when the forest agrees. Its rating is shown on
                every alert either way.
              </span>
            </span>
          </label>

          {test && plain && (
            <div className="muted small-text">
              Held-out test: with the forest precision {pct(test.precision)}, recall {pct(test.recall)}; the
              network alone {pct(plain.precision)} / {pct(plain.recall)}.
              {card.forest &&
                ` It overruled ${card.forest.overruled_alerts.toLocaleString()} alerts, of which ${card.forest.overruled_true_attacks.toLocaleString()} were real attacks.`}
            </div>
          )}
        </div>
      )}

      <div className="capture-actions wrap">
        {ACTIONS.map(([kind, label, hint]) => (
          <button
            key={kind}
            className={kind === "train" ? "btn primary small" : "btn small"}
            title={hint}
            disabled={busy || !!running || !model?.dataset_files}
            onClick={() => start(kind)}
          >
            {label}
          </button>
        ))}

        {running && (
          <button
            className="btn small danger"
            onClick={() => act(() => send(`/api/jobs/${running.id}/cancel`, "POST"))}
          >
            Cancel
          </button>
        )}

        <button
          className="btn small"
          disabled={busy || !model?.previous_available}
          title="Swap back to the model used before the last retraining"
          onClick={() => {
            if (window.confirm("Switch to the previous model?"))
              act(() => send("/api/model/rollback", "POST"));
          }}
        >
          Roll back
        </button>
      </div>

      {model && !model.dataset_files && (
        <div className="muted small-text">
          Retraining needs CIC-IDS-2017 CSVs: upload them in the Data section.
        </div>
      )}

      {error && <div className="error">{error}</div>}

      {shown && <JobLog job={shown} onDone={load} />}

      {jobs.length > 1 && (
        <div className="small-text muted history">
          Earlier:{" "}
          {jobs
            .filter((j) => j.id !== shown?.id)
            .slice(0, 5)
            .map((j) => (
              <button className="link" key={j.id} onClick={() => setShown(j)}>
                #{j.id} {j.kind} ({j.state})
              </button>
            ))}
        </div>
      )}
    </div>
  );
}
