import { useEffect, useState } from "react";

import { getJSON, send, setToken } from "../api.js";
import PushCard from "./PushCard.jsx";
import { SessionsCard, TwoFactorCard } from "./SecurityCards.jsx";

const EMPTY = { current: "", username: "", password: "", again: "", code: "" };

/** Every signed-in person's own page: change your username and password. */
export default function AccountPanel() {
  const [me, setMe] = useState(null);
  const [form, setForm] = useState(EMPTY);
  const [error, setError] = useState("");
  const [note, setNote] = useState("");
  const [busy, setBusy] = useState(false);
  const [needCode, setNeedCode] = useState(false);

  useEffect(() => {
    getJSON("/api/account")
      .then((account) => {
        setMe(account);
        setForm((f) => ({ ...f, username: account.username }));
      })
      .catch((e) => setError(e.message));
  }, []);

  const set = (patch) => setForm((f) => ({ ...f, ...patch }));

  const submit = async (event) => {
    event.preventDefault();
    setError("");
    setNote("");

    const renamed = form.username.trim().toLowerCase() !== me.username;

    if (form.password && form.password !== form.again) {
      return setError("The new password and its repetition differ.");
    }

    const body = { current_password: form.current };

    if (renamed) body.new_username = form.username;
    if (form.password) body.new_password = form.password;
    if (form.code.trim()) body.code = form.code;

    if (!renamed && !form.password) return setError("Change the username or enter a new password.");

    setBusy(true);

    try {
      const done = await send("/api/account", "PATCH", body);

      // the old sessions ended; this is the fresh one
      setToken(done.token);
      setMe({ ...me, username: done.username });
      setForm({ ...EMPTY, username: done.username });
      setNeedCode(false);
      setNote(
        [renamed && "Username changed.", form.password && "Password changed."]
          .filter(Boolean)
          .join(" ") + " Other devices must sign in again."
      );
    } catch (e) {
      // with two-factor sign-in on, a change also needs a code
      if (e.twoFactor) setNeedCode(true);

      setError(e.message);
    }

    setBusy(false);
  };

  if (!me) return <div className="card">{error || "Loading…"}</div>;

  if (!me.editable) {
    return (
      <div className="card account">
        <h2>Account</h2>
        <p className="muted">
          You are using {me.via === "token" ? "the shared admin token" : "an open dashboard"}, not a
          named account, so there is no username or password to change here. Create accounts
          under Operations → Users.
        </p>
      </div>
    );
  }

  return (
    <div className="account-page">
    <form className="card account" onSubmit={submit}>
      <h2>Account</h2>

      <p className="muted small-text">
        Signed in as <b>{me.username}</b> · {me.role}
        {me.last_login && <> · last sign-in {me.last_login.replace("T", " ")}</>}
      </p>

      <label className="stack">
        <span>Username</span>
        <input
          autoComplete="username"
          value={form.username}
          onChange={(e) => set({ username: e.target.value })}
        />
        <span className="muted small-text">2–32 characters: letters, digits, . _ -</span>
      </label>

      <label className="stack">
        <span>New password (leave empty to keep the current one)</span>
        <input
          type="password"
          autoComplete="new-password"
          value={form.password}
          onChange={(e) => set({ password: e.target.value })}
        />
        <span className="muted small-text">At least 10 characters.</span>
      </label>

      {form.password && (
        <label className="stack">
          <span>New password again</span>
          <input
            type="password"
            autoComplete="new-password"
            value={form.again}
            onChange={(e) => set({ again: e.target.value })}
          />
        </label>
      )}

      <label className="stack">
        <span>Current password (required to save)</span>
        <input
          type="password"
          autoComplete="current-password"
          value={form.current}
          onChange={(e) => set({ current: e.target.value })}
        />
      </label>

      {(needCode || me.two_factor) && (
        <label className="stack">
          <span>Code from your authenticator app</span>
          <input
            inputMode="numeric"
            autoComplete="one-time-code"
            value={form.code}
            onChange={(e) => set({ code: e.target.value })}
          />
        </label>
      )}

      {error && <div className="error">{error}</div>}
      {note && <div className="note">{note}</div>}

      <button className="btn primary" disabled={busy || !form.current}>
        {busy ? "Saving…" : "Save changes"}
      </button>
    </form>

    <TwoFactorCard />

    <PushCard />

    <SessionsCard />
    </div>
  );
}
