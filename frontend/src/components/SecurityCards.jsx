import qrcode from "qrcode-generator";
import { useEffect, useMemo, useState } from "react";

import { getJSON, send } from "../api.js";

/** A QR code for an authenticator app, drawn in the browser: the secret never leaves this page. */
function QrCode({ text }) {
  const svg = useMemo(() => {
    const qr = qrcode(0, "M");

    qr.addData(text);
    qr.make();

    return qr.createSvgTag({ cellSize: 4, margin: 2, scalable: true });
  }, [text]);

  // the markup is drawn by the QR library from our own text: there is no user HTML in it
  return <div className="qr" dangerouslySetInnerHTML={{ __html: svg }} />;
}

/** Turn two-factor sign-in on or off. The password is asked again for both. */
export function TwoFactorCard() {
  const [status, setStatus] = useState(null);
  const [step, setStep] = useState("idle");
  const [setup, setSetup] = useState(null);
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [recovery, setRecovery] = useState(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [copied, setCopied] = useState(false);

  const load = () =>
    getJSON("/api/account/two-factor")
      .then(setStatus)
      .catch((e) => setError(e.message));

  useEffect(() => {
    load();
  }, []);

  const reset = () => {
    setStep("idle");
    setSetup(null);
    setPassword("");
    setCode("");
    setError("");
  };

  const run = async (fn) => {
    setBusy(true);
    setError("");

    try {
      await fn();
    } catch (e) {
      setError(e.message);
    }

    setBusy(false);
  };

  const start = (event) => {
    event.preventDefault();

    run(async () => {
      setSetup(await send("/api/account/two-factor/start", "POST", { current_password: password }));
      setPassword("");
      setStep("scan");
    });
  };

  const confirm = (event) => {
    event.preventDefault();

    run(async () => {
      const done = await send("/api/account/two-factor/confirm", "POST", { code });

      setRecovery(done.recovery_codes);
      setStep("codes");
      setSetup(null);
      setCode("");
      await load();
    });
  };

  const disable = (event) => {
    event.preventDefault();

    run(async () => {
      await send("/api/account/two-factor/disable", "POST", { current_password: password, code });

      reset();
      await load();
    });
  };

  const copyCodes = async () => {
    try {
      await navigator.clipboard.writeText(recovery.join("\n"));
      setCopied(true);
    } catch {
      /* the codes are on screen: they can be copied by hand */
    }
  };

  if (!status) return <div className="card account">{error || "Loading…"}</div>;

  return (
    <div className="card account">
      <h2>
        Two-factor sign-in <span className={status.enabled ? "pill on" : "pill"}>{status.enabled ? "on" : "off"}</span>
      </h2>

      {step === "codes" && recovery && (
        <>
          <div className="note">
            Two-factor sign-in is on. Keep these recovery codes somewhere safe: each works once if you lose
            your phone. They are shown only now.
          </div>

          <ul className="recovery">
            {recovery.map((c) => (
              <li key={c}>{c}</li>
            ))}
          </ul>

          <div className="row-actions">
            <button className="btn small" onClick={copyCodes}>
              {copied ? "Copied" : "Copy"}
            </button>
            <button
              className="btn primary small"
              onClick={() => {
                setRecovery(null);
                reset();
              }}
            >
              I have saved them
            </button>
          </div>
        </>
      )}

      {step !== "codes" && !status.enabled && step === "idle" && (
        <>
          <p className="muted small-text">
            Signing in then needs a 6-digit code from an authenticator app (Google Authenticator, Microsoft
            Authenticator, Aegis, 1Password…) as well as your password, so a stolen password alone is no
            longer enough.
          </p>

          <button className="btn primary" onClick={() => setStep("password")}>
            Set up two-factor sign-in
          </button>
        </>
      )}

      {step === "password" && (
        <form className="account-form" onSubmit={start}>
          <label className="stack">
            <span>Confirm with your password</span>
            <input
              type="password"
              autoComplete="current-password"
              autoFocus
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
          </label>

          {error && <div className="error">{error}</div>}

          <div className="row-actions">
            <button className="btn primary" disabled={busy || !password}>
              Continue
            </button>
            <button type="button" className="btn" onClick={reset}>
              Cancel
            </button>
          </div>
        </form>
      )}

      {step === "scan" && setup && (
        <form className="account-form" onSubmit={confirm}>
          <p className="muted small-text">
            1. Scan this code with your authenticator app, or enter the key by hand.
          </p>

          <QrCode text={setup.uri} />

          <code className="secret">{setup.secret.match(/.{1,4}/g).join(" ")}</code>

          <label className="stack">
            <span>2. Enter the 6-digit code the app shows</span>
            <input
              inputMode="numeric"
              autoComplete="one-time-code"
              autoFocus
              value={code}
              onChange={(e) => setCode(e.target.value)}
            />
          </label>

          {error && <div className="error">{error}</div>}

          <div className="row-actions">
            <button className="btn primary" disabled={busy || code.replace(/\s/g, "").length < 6}>
              Turn on
            </button>
            <button type="button" className="btn" onClick={reset}>
              Cancel
            </button>
          </div>
        </form>
      )}

      {status.enabled && step !== "codes" && step !== "disable" && (
        <>
          <p className="muted small-text">
            A code from your authenticator app is needed at every sign-in. {status.recovery_left} recovery{" "}
            {status.recovery_left === 1 ? "code is" : "codes are"} left.
          </p>

          <button className="btn danger" onClick={() => setStep("disable")}>
            Turn off…
          </button>
        </>
      )}

      {step === "disable" && (
        <form className="account-form" onSubmit={disable}>
          <label className="stack">
            <span>Your password</span>
            <input
              type="password"
              autoComplete="current-password"
              autoFocus
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
          </label>

          <label className="stack">
            <span>A code from the app (or a recovery code)</span>
            <input autoComplete="one-time-code" value={code} onChange={(e) => setCode(e.target.value)} />
          </label>

          {error && <div className="error">{error}</div>}

          <div className="row-actions">
            <button className="btn danger" disabled={busy || !password || !code}>
              Turn off two-factor
            </button>
            <button type="button" className="btn" onClick={reset}>
              Cancel
            </button>
          </div>
        </form>
      )}

      {error && step === "idle" && <div className="error">{error}</div>}
    </div>
  );
}

/** The devices signed in as this person, with a way to end all the others. */
export function SessionsCard() {
  const [sessions, setSessions] = useState(null);
  const [note, setNote] = useState("");
  const [error, setError] = useState("");

  const load = () =>
    getJSON("/api/account/sessions")
      .then(setSessions)
      .catch((e) => setError(e.message));

  useEffect(() => {
    load();
  }, []);

  const signOutOthers = async () => {
    setError("");

    try {
      const { ended } = await send("/api/account/sessions/sign-out-others", "POST");

      setNote(`${ended} other ${ended === 1 ? "session" : "sessions"} signed out.`);
      await load();
    } catch (e) {
      setError(e.message);
    }
  };

  if (!sessions) return <div className="card account">{error || "Loading…"}</div>;

  const others = sessions.filter((s) => !s.current).length;

  return (
    <div className="card account">
      <h2>Where you are signed in</h2>

      <ul className="sessions">
        {sessions.map((s) => (
          <li key={s.id}>
            <span>
              {s.client || "unknown address"}
              {s.current && <span className="pill on">this device</span>}
            </span>
            <span className="muted small-text">since {s.created_at.replace("T", " ")}</span>
          </li>
        ))}
      </ul>

      {error && <div className="error">{error}</div>}
      {note && <div className="note">{note}</div>}

      <button className="btn" disabled={!others} onClick={signOutOthers}>
        Sign out all other devices
      </button>
    </div>
  );
}
