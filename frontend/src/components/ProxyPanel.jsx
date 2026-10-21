import { useEffect, useState } from "react";

import { getJSON, getToken, send, unauthorized } from "../api.js";
import { apiUrl } from "../config.js";

const ENGINES = {
  caddy: {
    name: "Caddy",
    blurb: "Automatic HTTPS, the simplest to run. Gets a real certificate by itself for a public name."
  },
  nginx: {
    name: "nginx",
    blurb: "The widely used web server. Uses a self-signed certificate, or your own files."
  }
};

const EMPTY_FORM = {
  engine: "caddy",
  address: "localhost",
  port: 8443,
  expose: false,
  tls: "internal",
  cert: null,
  key: null,
  autostart: false
};

function Badge({ running, installed }) {
  const [color, text] = running
    ? ["#4cc38a", "Running"]
    : installed
      ? ["#8b95a7", "Stopped"]
      : ["#f7d154", "Not installed"];

  return (
    <span
      className="badge"
      style={{ color, borderColor: color + "55", background: color + "18" }}
    >
      {text}
    </span>
  );
}

export default function ProxyPanel() {
  const [status, setStatus] = useState(null);
  const [form, setForm] = useState(EMPTY_FORM);
  const [busy, setBusy] = useState("");
  const [error, setError] = useState("");
  const [note, setNote] = useState("");
  const [testResult, setTestResult] = useState(null);
  const [cert, setCert] = useState(null);
  const [log, setLog] = useState(null);
  const [unsigned, setUnsigned] = useState(false);

  const load = async (adopt = false) => {
    try {
      const data = await getJSON("/api/proxy");

      setStatus(data);

      if (adopt) setForm({ ...EMPTY_FORM, ...data.settings });

      return data;
    } catch {
      return null;
    }
  };

  useEffect(() => {
    load(true);

    const timer = setInterval(() => load(false), 6000);

    return () => clearInterval(timer);
  }, []);

  const set = (patch) => setForm((f) => ({ ...f, ...patch }));

  const run = async (label, fn) => {
    setBusy(label);
    setError("");
    setNote("");

    try {
      await fn();
    } catch (e) {
      setError(e.message);
    }

    setBusy("");

    await load(false);
  };

  const engine = form.engine;

  const info = status?.installed?.[engine];

  const installed = !!info?.installed;

  const running = !!status?.running;

  const saved = status?.settings;

  const dirty = saved && JSON.stringify(saved) !== JSON.stringify({ ...saved, ...form });

  const payload = () => ({
    engine,
    address: form.address,
    port: Number(form.port),
    expose: form.expose,
    autostart: form.autostart,
    ...(engine === "caddy"
      ? { tls: form.tls }
      : { cert: form.cert || null, key: form.key || null })
  });

  const save = () =>
    run("save", async () => {
      const data = await send("/api/proxy/settings", "PUT", payload());

      setStatus(data);
      setNote(running ? "Saved. Restart the proxy to apply it." : "Saved.");
    });

  const install = () =>
    run("install", async () => {
      const data = await send("/api/proxy/install", "POST", {
        engine,
        allow_unverified: unsigned
      });

      setStatus(data);
      setNote(`${ENGINES[engine].name} installed: ${data.installed[engine].verified}.`);
    });

  const control = (action, text) =>
    run(action, async () => {
      // settings first, so Start uses what is on screen
      if (dirty) await send("/api/proxy/settings", "PUT", payload());

      setStatus(await send(`/api/proxy/${action}`, "POST"));

      setNote(text);
      setTestResult(null);
    });

  const test = () =>
    run("test", async () => setTestResult(await send("/api/proxy/test", "POST")));

  const showCertificate = () =>
    run("cert", async () => setCert(await getJSON("/api/proxy/certificate")));

  const downloadCertificate = async () => {
    const token = getToken();

    const response = await fetch(apiUrl("/api/proxy/certificate/download"), {
      headers: token ? { Authorization: `Bearer ${token}` } : {}
    });

    if (response.status === 401) return unauthorized();

    if (!response.ok) {
      const body = await response.json().catch(() => ({}));
      return setError(body.detail || "Could not download the certificate.");
    }

    const url = URL.createObjectURL(await response.blob());

    const link = document.createElement("a");

    link.href = url;
    link.download = "ids-proxy-certificate.crt";
    link.click();

    URL.revokeObjectURL(url);
  };

  const showLog = async () => {
    if (log !== null) return setLog(null);

    setLog((await getJSON("/api/proxy/log?lines=80")).log || "(empty)");
  };

  const proxyMode = () => {
    if (!window.confirm("Restart the dashboard in proxy mode? It is back in about ten seconds."))
      return;

    run("mode", async () => {
      await send("/api/server/restart", "POST", { behind_proxy: true });

      setNote("Restarting the dashboard…");

      setTimeout(() => location.reload(), 12000);
    });
  };

  if (!status) return null;

  return (
    <div className="card">
      <div className="card-head">
        <h2>HTTPS proxy</h2>
        <Badge running={running} installed={installed} />
      </div>

      <div className="muted small-text">
        A proxy in front of the dashboard provides HTTPS and handles large uploads. Pick one,
        install it here, and start it. Nothing is installed system-wide.
      </div>

      <div className="engines">
        {Object.entries(ENGINES).map(([key, e]) => {
          const m = status.installed[key];

          return (
            <label
              key={key}
              className={`engine ${engine === key ? "chosen" : ""} ${running && engine !== key ? "locked" : ""}`}
            >
              <input
                type="radio"
                name="engine"
                checked={engine === key}
                disabled={running && engine !== key}
                onChange={() =>
                  set({
                    engine: key,
                    tls: key === "caddy" ? "internal" : form.tls
                  })
                }
              />
              <b>{e.name}</b>
              <span className="muted small-text">{e.blurb}</span>
              <span className="small-text">
                {m?.installed ? (
                  m.intact ? (
                    <span className="ok">
                      installed {m.version} · {m.verified}
                    </span>
                  ) : (
                    <span className="miss">
                      installed, but the program no longer matches the checksum recorded
                      at install. Install again.
                    </span>
                  )
                ) : (
                  <span className="muted">not installed</span>
                )}
              </span>
            </label>
          );
        })}
      </div>

      {(!installed || !info?.intact) && (
        <>
          {engine === "nginx" && !status.gpg_available && (
            <label className="check small-text">
              <input
                type="checkbox"
                checked={unsigned}
                onChange={(e) => setUnsigned(e.target.checked)}
              />
              GnuPG is not installed, so nginx's signature cannot be checked. Install it
              anyway (downloaded over HTTPS from nginx.org).
            </label>
          )}

          <div className="capture-actions">
            <button className="btn primary small" disabled={!!busy} onClick={install}>
              {busy === "install" ? "Downloading and verifying…" : `Install ${ENGINES[engine].name}`}
            </button>
          </div>
        </>
      )}

      {installed && info?.intact && (
        <>
          <div className="form-grid">
            <label className="stack">
              <span>Address people will use</span>
              <input
                value={form.address}
                disabled={running}
                onChange={(e) => set({ address: e.target.value })}
              />
            </label>

            <label className="stack">
              <span>Port</span>
              <input
                type="number"
                min="1"
                max="65535"
                value={form.port}
                disabled={running}
                onChange={(e) => set({ port: e.target.value })}
              />
            </label>
          </div>

          <label className="check small-text">
            <input
              type="checkbox"
              checked={form.expose}
              disabled={running}
              onChange={(e) => set({ expose: e.target.checked })}
            />
            Let other computers connect (otherwise only this computer can)
          </label>

          {form.expose && (
            <div className="warnbox">
              Other computers on your network will be able to reach the dashboard. Create an
              account first (Users), because without sign-in anyone could use it.
            </div>
          )}

          {engine === "caddy" ? (
            <label className="stack">
              <span>Certificate</span>
              <select
                value={form.tls === "internal" ? "internal" : "acme"}
                disabled={running}
                onChange={(e) => set({ tls: e.target.value === "internal" ? "internal" : "" })}
              >
                <option value="internal">Caddy's own local certificate (browsers ask to trust it)</option>
                <option value="acme">A real certificate from Let's Encrypt (needs a public name)</option>
              </select>

              {form.tls !== "internal" && (
                <input
                  placeholder="your email address, for Let's Encrypt"
                  value={form.tls}
                  disabled={running}
                  onChange={(e) => set({ tls: e.target.value })}
                />
              )}
            </label>
          ) : (
            <div className="form-grid">
              <label className="stack">
                <span>Certificate file</span>
                <select
                  value={form.cert || ""}
                  disabled={running}
                  onChange={(e) => set({ cert: e.target.value || null })}
                >
                  <option value="">Generate a self-signed one</option>
                  {status.certificates
                    .filter((n) => !n.toLowerCase().endsWith(".key"))
                    .map((n) => (
                      <option key={n}>{n}</option>
                    ))}
                </select>
              </label>

              <label className="stack">
                <span>Private key file</span>
                <select
                  value={form.key || ""}
                  disabled={running || !form.cert}
                  onChange={(e) => set({ key: e.target.value || null })}
                >
                  <option value="">(none)</option>
                  {status.certificates
                    .filter((n) => n.toLowerCase().endsWith(".key"))
                    .map((n) => (
                      <option key={n}>{n}</option>
                    ))}
                </select>
              </label>
            </div>
          )}

          {engine === "nginx" && (
            <div className="muted small-text">
              Upload your own certificate and key under Data &gt; TLS certificates.
            </div>
          )}

          <label className="check small-text">
            <input
              type="checkbox"
              checked={form.autostart}
              onChange={(e) => set({ autostart: e.target.checked })}
            />
            Start the proxy when the dashboard starts
          </label>

          <div className="capture-actions wrap">
            {running ? (
              <>
                <button className="btn small danger" disabled={!!busy} onClick={() => control("stop", "Stopped.")}>
                  Stop
                </button>
                <button className="btn small" disabled={!!busy} onClick={() => control("restart", "Restarted.")}>
                  Restart
                </button>
              </>
            ) : (
              <button
                className="btn primary small"
                disabled={!!busy}
                onClick={() => control("start", "Started.")}
              >
                {busy === "start" ? "Starting…" : "Start"}
              </button>
            )}

            <button className="btn small" disabled={!!busy || !dirty} onClick={save}>
              Save settings
            </button>

            <button className="btn small" disabled={!!busy || !running} onClick={test}>
              Test
            </button>

            {running && (
              <a className="btn small" href={status.url} target="_blank" rel="noreferrer">
                Open {status.url}
              </a>
            )}
          </div>

          {running && !status.dashboard_behind_proxy && (
            <div className="warnbox">
              The dashboard is not in proxy mode, so it would show the proxy's address instead
              of each visitor's, and would not tell browsers to insist on HTTPS.{" "}
              {status.can_switch_proxy_mode ? (
                <button className="link" onClick={proxyMode}>
                  Restart the dashboard in proxy mode
                </button>
              ) : (
                "Start it with serve.py --behind-proxy."
              )}
            </div>
          )}

          {testResult && (
            <div className={testResult.ok ? "small-text ok" : "error"}>
              {testResult.ok ? (
                <>
                  Reached the dashboard through the proxy over {testResult.tls} in{" "}
                  {testResult.milliseconds} ms. HSTS {testResult.hsts ? "on" : "off"}.
                  {testResult.server_banner ? ` Server banner: ${testResult.server_banner}.` : ""}
                </>
              ) : (
                testResult.error ||
                `The proxy answered, but the dashboard did not look healthy (HTTP ${testResult.http_status}).`
              )}
            </div>
          )}

          <div className="capture-actions wrap">
            <button className="link" onClick={showCertificate}>
              Certificate
            </button>
            <button className="link" onClick={showLog}>
              {log === null ? "Show proxy log" : "Hide proxy log"}
            </button>
          </div>

          {cert && (
            <div className="newkey small-text">
              <div>
                <b>{cert.kind}</b>, expires {cert.expires}
              </div>
              <div className="mono">SHA-256 {cert.fingerprint}</div>
              <div className="muted">
                Browsers warn about this certificate until it is trusted. Download it, open it,
                choose <i>Install Certificate</i> for the current user and put it in
                <i> Trusted Root Certification Authorities</i> (Windows) or Keychain Access
                (macOS). Compare the fingerprint first.
              </div>
              <button className="btn small" onClick={downloadCertificate}>
                Download certificate
              </button>
            </div>
          )}

          {log !== null && <pre className="logbox">{log}</pre>}
        </>
      )}

      {note && <div className="small-text ok">{note}</div>}

      {error && <div className="error pre">{error}</div>}
    </div>
  );
}
