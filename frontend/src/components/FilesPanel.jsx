import { useEffect, useRef, useState } from "react";

import { getJSON, getToken, send, unauthorized } from "../api.js";
import { apiUrl } from "../config.js";

const AREAS = {
  dataset: {
    title: "Training data",
    help: "CIC-IDS-2017 CSVs (MachineLearningCSV). Add the other days to teach the model more attack types, then retrain.",
    accept: ".csv"
  },
  certs: {
    title: "TLS certificates",
    help: "PEM files for the nginx proxy: a certificate (.crt or .pem) and its private key (.key). Private keys are kept on the server and never shown again.",
    accept: ".pem,.crt,.cer,.key"
  },
  captures: {
    title: "Capture files",
    help: "pcap / pcapng files and flow CSVs the Capture panel can open.",
    accept: ".pcap,.pcapng,.cap,.csv"
  }
};

const size = (bytes) =>
  bytes > 1e9
    ? `${(bytes / 1e9).toFixed(1)} GB`
    : bytes > 1e6
      ? `${(bytes / 1e6).toFixed(1)} MB`
      : `${Math.max(1, Math.round(bytes / 1e3))} KB`;

/** PUT a file's bytes with progress (fetch cannot report upload progress). */
function putFile(url, file, onProgress) {
  return new Promise((resolve, reject) => {
    const request = new XMLHttpRequest();

    request.open("PUT", apiUrl(url));

    const token = getToken();

    if (token) request.setRequestHeader("Authorization", `Bearer ${token}`);

    request.upload.onprogress = (e) => e.lengthComputable && onProgress(e.loaded / e.total);

    request.onload = () => {
      if (request.status === 401) unauthorized();

      if (request.status >= 200 && request.status < 300) return resolve();

      let detail = `${request.status}`;

      try {
        detail = JSON.parse(request.responseText).detail || detail;
      } catch {
        /* not JSON */
      }

      reject(new Error(detail));
    };

    request.onerror = () => reject(new Error("the connection was interrupted"));

    request.send(file);
  });
}

function Area({ area, entries, folder, maxMb, reload }) {
  const { title, help, accept } = AREAS[area];
  const input = useRef(null);
  const [progress, setProgress] = useState(null);
  const [replace, setReplace] = useState(false);
  const [error, setError] = useState("");
  const [over, setOver] = useState(false);

  const uploadAll = async (list) => {
    setError("");

    for (const file of list) {
      // the server would refuse it anyway; say so before sending gigabytes
      if (file.size > maxMb * 1024 * 1024) {
        setError(
          `${file.name} is ${size(file.size)}, over the ${maxMb} MB limit. ` +
            "An administrator can raise it with IDS_MAX_UPLOAD_MB."
        );
        break;
      }

      setProgress({ name: file.name, done: 0 });

      try {
        await putFile(
          `/api/files/${area}/${encodeURIComponent(file.name)}${replace ? "?replace=true" : ""}`,
          file,
          (done) => setProgress({ name: file.name, done })
        );
      } catch (e) {
        setError(`${file.name}: ${e.message}`);
        break;
      }
    }

    setProgress(null);
    reload();
  };

  const remove = async (name) => {
    if (!window.confirm(`Delete ${name}?`)) return;

    try {
      await send(`/api/files/${area}/${encodeURIComponent(name)}`, "DELETE");
      reload();
    } catch (e) {
      setError(e.message);
    }
  };

  return (
    <div className="files-area">
      <h3>{title}</h3>
      <div className="muted small-text">{help}</div>

      <div
        className={`dropzone ${over ? "over" : ""}`}
        onDragOver={(e) => {
          e.preventDefault();
          setOver(true);
        }}
        onDragLeave={() => setOver(false)}
        onDrop={(e) => {
          e.preventDefault();
          setOver(false);
          uploadAll([...e.dataTransfer.files]);
        }}
        onClick={() => input.current.click()}
      >
        {progress ? (
          <>
            <div className="small-text">
              Uploading {progress.name} {Math.round(progress.done * 100)}%
            </div>
            <div className="bar">
              <div style={{ width: `${progress.done * 100}%`, background: "var(--accent)" }} />
            </div>
          </>
        ) : (
          <>Drop files here or click to choose (up to {maxMb} MB each)</>
        )}

        <input
          ref={input}
          type="file"
          multiple
          accept={accept}
          hidden
          onChange={(e) => {
            uploadAll([...e.target.files]);
            e.target.value = "";
          }}
        />
      </div>

      <label className="check small-text">
        <input type="checkbox" checked={replace} onChange={(e) => setReplace(e.target.checked)} />
        Replace a file with the same name
      </label>

      {error && <div className="error">{error}</div>}

      {entries.map((f) => (
        <div className="file" key={f.name}>
          <div className="file-head">
            <span className="mono">{f.name}</span>
            <span className="muted small-text">
              {size(f.size)} · {f.modified.slice(0, 10)}{" "}
              <button className="link danger-text" onClick={() => remove(f.name)}>
                delete
              </button>
            </span>
          </div>

          {area === "dataset" &&
            (f.labels ? (
              <div className="chips">
                {Object.entries(f.labels).map(([label, n]) => (
                  <span className="chip" key={label}>
                    {label} <b>{n.toLocaleString()}</b>
                  </span>
                ))}
              </div>
            ) : f.error ? (
              <div className="error">{f.error}</div>
            ) : (
              <div className="muted small-text">counting labels…</div>
            ))}
        </div>
      ))}

      {!entries.length && <div className="muted small-text">No files yet.</div>}

      <div className="muted small-text path">{folder}</div>
    </div>
  );
}

export default function FilesPanel({ revision }) {
  const [data, setData] = useState(null);

  const load = () =>
    getJSON("/api/files")
      .then(setData)
      .catch(() => {});

  useEffect(() => {
    load();
  }, [revision]);

  // label counts for big files arrive a few seconds after the upload
  useEffect(() => {
    if (!data?.dataset.some((f) => f.labels === null && !f.error)) return;

    const timer = setTimeout(load, 2500);

    return () => clearTimeout(timer);
  }, [data]);

  return (
    <div className="card">
      <div className="card-head">
        <h2>Data</h2>
      </div>

      {data &&
        Object.keys(AREAS).map((area) => (
          <Area
            key={area}
            area={area}
            entries={data[area]}
            folder={data[`${area}_dir`]}
            maxMb={data.max_upload_mb}
            reload={load}
          />
        ))}
    </div>
  );
}
