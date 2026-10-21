import { useEffect, useState } from "react";

import { getJSON, send } from "../api.js";

const LEVELS = ["Medium", "High", "Critical"];
const SOURCES = [
  ["capture", "Live capture"],
  ["api", "API"],
  ["replay", "Demo replay"]
];
const FORMATS = ["slack", "discord", "teams", "mattermost", "generic"];

const EMPTY = {
  min_risk: "High",
  sources: ["capture", "api"],
  window_seconds: 10,
  base_url: location.origin,
  webhook: { enabled: false, format: "slack", url: "", has_url: false },
  email: {
    enabled: false,
    host: "",
    port: 587,
    starttls: true,
    username: "",
    password: "",
    has_password: false,
    from: "",
    to: ""
  }
};

/** Server settings -> form values (secrets stay blank; "has_*" says one is stored). */
function toForm(settings) {
  if (!settings) return EMPTY;

  return {
    min_risk: settings.min_risk,
    sources: settings.sources,
    window_seconds: settings.window_seconds,
    base_url: settings.base_url,
    webhook: settings.webhook
      ? { ...EMPTY.webhook, ...settings.webhook, url: "" }
      : EMPTY.webhook,
    email: settings.email
      ? { ...EMPTY.email, ...settings.email, password: "", to: settings.email.to.join(", ") }
      : EMPTY.email
  };
}

/** Form values -> what the server expects. Blank secrets are left out (kept). */
function toPayload(form) {
  const { webhook, email } = form;

  return {
    min_risk: form.min_risk,
    sources: form.sources,
    window_seconds: Number(form.window_seconds),
    base_url: form.base_url,
    webhook: {
      enabled: webhook.enabled,
      format: webhook.format,
      ...(webhook.url ? { url: webhook.url } : {})
    },
    email: {
      enabled: email.enabled,
      host: email.host,
      port: Number(email.port),
      starttls: email.starttls,
      username: email.username,
      from: email.from,
      to: email.to.split(/[,\s]+/).filter(Boolean),
      ...(email.password ? { password: email.password } : {})
    }
  };
}

export default function NotificationSettings({ onChanged }) {
  const [source, setSource] = useState(null);
  const [problem, setProblem] = useState(null);
  const [form, setForm] = useState(EMPTY);
  const [message, setMessage] = useState({ text: "", bad: false });
  const [busy, setBusy] = useState(false);

  const load = () =>
    getJSON("/api/notifications/config")
      .then((data) => {
        setSource(data.source);
        setProblem(data.problem || null);
        setForm(toForm(data.settings));
      })
      .catch(() => {});

  useEffect(() => {
    load();
  }, []);

  const set = (patch) => setForm((f) => ({ ...f, ...patch }));

  const setHook = (patch) => setForm((f) => ({ ...f, webhook: { ...f.webhook, ...patch } }));

  const setMail = (patch) => setForm((f) => ({ ...f, email: { ...f.email, ...patch } }));

  const toggleSource = (name) =>
    set({
      sources: form.sources.includes(name)
        ? form.sources.filter((s) => s !== name)
        : [...form.sources, name]
    });

  const run = async (fn, ok) => {
    setBusy(true);
    setMessage({ text: "", bad: false });

    try {
      const result = await fn();

      setMessage({ text: ok(result), bad: false });
    } catch (e) {
      setMessage({ text: e.message, bad: true });
    }

    setBusy(false);
  };

  const save = () =>
    run(
      async () => {
        const saved = await send("/api/notifications/config", "PUT", toPayload(form));

        setSource(saved.source);
        setProblem(null);
        setForm(toForm(saved.settings));
        onChanged?.();

        return saved;
      },
      () => "Saved. Alerts use these settings from now on."
    );

  const test = () =>
    run(
      () => send("/api/notifications/test", "POST"),
      (result) =>
        Object.entries(result)
          .map(([channel, r]) => `${channel}: ${r.ok ? "sent" : r.error}`)
          .join(" · ")
    );

  const { webhook, email } = form;

  return (
    <div className="card">
      <div className="card-head">
        <h2>Notifications</h2>
        <span className="muted small-text">
          {source === "dashboard"
            ? "managed here"
            : source === "file"
              ? "from notify.json"
              : "not set up"}
        </span>
      </div>

      {problem && <div className="error">{problem}</div>}

      {source === "file" && (
        <div className="muted small-text">
          Notifications currently come from <code>notify.json</code>. Saving here replaces
          that file's settings.
        </div>
      )}

      <div className="form-grid">
        <label className="stack">
          <span>Notify from risk level</span>
          <select value={form.min_risk} onChange={(e) => set({ min_risk: e.target.value })}>
            {LEVELS.map((l) => (
              <option key={l}>{l}</option>
            ))}
          </select>
        </label>

        <label className="stack">
          <span>Digest every (seconds)</span>
          <input
            type="number"
            min="1"
            max="3600"
            value={form.window_seconds}
            onChange={(e) => set({ window_seconds: e.target.value })}
          />
        </label>
      </div>

      <div className="small-text">
        <span className="muted">Alerts from: </span>
        {SOURCES.map(([name, label]) => (
          <label className="inline-check" key={name}>
            <input
              type="checkbox"
              checked={form.sources.includes(name)}
              onChange={() => toggleSource(name)}
            />
            {label}
          </label>
        ))}
      </div>

      <label className="stack">
        <span>Dashboard address (used in links)</span>
        <input value={form.base_url} onChange={(e) => set({ base_url: e.target.value })} />
      </label>

      <h3>Chat webhook</h3>

      <label className="check">
        <input
          type="checkbox"
          checked={webhook.enabled}
          onChange={(e) => setHook({ enabled: e.target.checked })}
        />
        Send digests to a webhook
      </label>

      {webhook.enabled && (
        <div className="form-grid">
          <label className="stack">
            <span>Service</span>
            <select value={webhook.format} onChange={(e) => setHook({ format: e.target.value })}>
              {FORMATS.map((f) => (
                <option key={f}>{f}</option>
              ))}
            </select>
          </label>

          <label className="stack">
            <span>Webhook URL</span>
            <input
              type="password"
              autoComplete="off"
              placeholder={webhook.has_url ? "saved (leave blank to keep)" : "https://…"}
              value={webhook.url}
              onChange={(e) => setHook({ url: e.target.value })}
            />
          </label>
        </div>
      )}

      <h3>Email</h3>

      <label className="check">
        <input
          type="checkbox"
          checked={email.enabled}
          onChange={(e) => setMail({ enabled: e.target.checked })}
        />
        Send digests by email
      </label>

      {email.enabled && (
        <>
          <div className="form-grid">
            <label className="stack">
              <span>SMTP server</span>
              <input value={email.host} onChange={(e) => setMail({ host: e.target.value })} />
            </label>

            <label className="stack">
              <span>Port</span>
              <input
                type="number"
                value={email.port}
                onChange={(e) => setMail({ port: e.target.value })}
              />
            </label>

            <label className="stack">
              <span>Username</span>
              <input
                autoComplete="off"
                value={email.username}
                onChange={(e) => setMail({ username: e.target.value })}
              />
            </label>

            <label className="stack">
              <span>Password</span>
              <input
                type="password"
                autoComplete="new-password"
                placeholder={email.has_password ? "saved (leave blank to keep)" : ""}
                value={email.password}
                onChange={(e) => setMail({ password: e.target.value })}
              />
            </label>

            <label className="stack">
              <span>From</span>
              <input value={email.from} onChange={(e) => setMail({ from: e.target.value })} />
            </label>

            <label className="stack">
              <span>To (comma separated)</span>
              <input value={email.to} onChange={(e) => setMail({ to: e.target.value })} />
            </label>
          </div>

          <label className="check small-text">
            <input
              type="checkbox"
              checked={email.starttls}
              onChange={(e) => setMail({ starttls: e.target.checked })}
            />
            Use STARTTLS (normal for port 587)
          </label>
        </>
      )}

      <div className="capture-actions">
        <button className="btn primary small" disabled={busy} onClick={save}>
          Save
        </button>
        <button
          className="btn small"
          disabled={busy || source === "none"}
          onClick={test}
          title="Sends a test message through every channel that is set up"
        >
          Send test
        </button>
      </div>

      {message.text && (
        <div className={message.bad ? "error" : "small-text ok"}>{message.text}</div>
      )}

      <div className="muted small-text">
        Webhook URLs and passwords are encrypted before they are stored.
      </div>
    </div>
  );
}
