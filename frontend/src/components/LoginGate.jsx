import { useCallback, useEffect, useState } from "react";

import { AuthContext } from "../auth.js";
import { getToken, setToken } from "../api.js";
import { apiUrl } from "../config.js";

async function whoAmI() {
  const token = getToken();

  const response = await fetch(apiUrl("/api/auth"), {
    headers: token ? { Authorization: `Bearer ${token}` } : {}
  });

  return response.json();
}

/**
 * Shows the sign-in page when the server requires one, and tells the
 * rest of the app who is signed in (see useAuth).
 */
export default function LoginGate({ children }) {
  const [auth, setAuth] = useState(null);
  const [needLogin, setNeedLogin] = useState(false);
  const [useToken, setUseToken] = useState(false);
  const [username, setUsername] = useState("");
  const [secret, setSecret] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const check = useCallback(async () => {
    try {
      const status = await whoAmI();

      setAuth(status);
      setNeedLogin(status.required && !status.ok);
    } catch {
      // server not reachable yet: show the dashboard, it retries itself
      setAuth({ required: false, ok: true, user: "local", role: "admin" });
    }
  }, []);

  useEffect(() => {
    check();

    // any API call that comes back 401 sends the user here
    const onUnauthorized = () => {
      setToken("");
      setNeedLogin(true);
    };

    window.addEventListener("ids-unauthorized", onUnauthorized);

    return () => window.removeEventListener("ids-unauthorized", onUnauthorized);
  }, [check]);

  const submit = async (event) => {
    event.preventDefault();
    setBusy(true);
    setError("");

    try {
      if (useToken) {
        setToken(secret.trim());

        const status = await whoAmI();

        if (!status.ok) {
          setToken("");
          throw new Error("That token was not accepted.");
        }
      } else {
        const response = await fetch(apiUrl("/api/login"), {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ username, password: secret })
        });

        const body = await response.json().catch(() => ({}));

        if (response.status === 429) {
          const wait = response.headers.get("Retry-After");
          throw new Error(
            `Too many failed attempts. Try again in ${Math.ceil(wait / 60) || 1} min.`
          );
        }

        if (!response.ok) throw new Error(body.detail || "Sign-in failed.");

        setToken(body.token);
      }

      location.reload();
    } catch (e) {
      setError(e.message);
      setBusy(false);
    }
  };

  if (!auth) return null;

  if (needLogin) {
    const tokenOnly = !auth.methods?.password && auth.methods?.token;

    const tokenMode = useToken || tokenOnly;

    return (
      <div className="login">
        <form className="card" onSubmit={submit}>
          <h1>Bayesian IDS</h1>

          <p className="muted">
            {tokenMode
              ? "This server requires an admin token."
              : "Sign in to continue."}
          </p>

          {!tokenMode && (
            <label className="stack">
              <span>Username</span>
              <input
                autoFocus
                autoComplete="username"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
              />
            </label>
          )}

          <label className="stack">
            <span>{tokenMode ? "Admin token" : "Password"}</span>
            <input
              type="password"
              autoFocus={tokenMode}
              autoComplete={tokenMode ? "off" : "current-password"}
              value={secret}
              onChange={(e) => setSecret(e.target.value)}
            />
          </label>

          {error && <div className="error">{error}</div>}

          <button
            className="btn primary"
            type="submit"
            disabled={busy || !secret.trim() || (!tokenMode && !username.trim())}
          >
            Sign in
          </button>

          {auth.methods?.password && auth.methods?.token && (
            <button
              type="button"
              className="link"
              onClick={() => {
                setUseToken(!useToken);
                setError("");
              }}
            >
              {useToken ? "Use username and password" : "Use the admin token instead"}
            </button>
          )}
        </form>
      </div>
    );
  }

  return (
    <AuthContext.Provider
      value={{
        user: auth.user || "local",
        role: auth.role || "admin",
        open: !auth.required
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}
