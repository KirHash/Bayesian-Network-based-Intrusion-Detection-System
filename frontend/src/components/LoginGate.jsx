import { useCallback, useEffect, useState } from "react";

import { AuthContext } from "../auth.js";
import { getToken, setToken } from "../api.js";
import { apiUrl } from "../config.js";
import AuthShell, { AuthField } from "./AuthShell.jsx";

async function whoAmI() {
  const token = getToken();

  const response = await fetch(apiUrl("/api/auth"), {
    headers: token ? { Authorization: `Bearer ${token}` } : {}
  });

  return response.json();
}

async function post(path, body) {
  let response;

  try {
    response = await fetch(apiUrl(path), {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body)
    });
  } catch {
    throw new Error("Cannot reach the server. Check your connection, or that the server is running, then try again.");
  }

  const data = await response.json().catch(() => ({}));

  if (response.status === 429) {
    const wait = Number(response.headers.get("Retry-After")) || 60;

    const error = new Error(data.detail || `Too many attempts. Try again in ${Math.ceil(wait / 60)} min.`);

    // the page counts the wait down and keeps the button off until it is over
    error.retryAfter = wait;

    throw error;
  }

  if (!response.ok) {
    const error = new Error(
      response.status >= 500
        ? data.detail || "The server had a problem. Try again in a moment."
        : data.detail || "That did not work."
    );

    // the password was right; the server wants the second factor
    error.twoFactor = data.two_factor === true;

    throw error;
  }

  return data;
}

/**
 * Shows the sign-in / sign-up page when the server requires one, and tells the
 * rest of the app who is signed in (see useAuth).
 */
export default function LoginGate({ children }) {
  const [auth, setAuth] = useState(null);
  const [needLogin, setNeedLogin] = useState(false);
  const [mode, setMode] = useState("login");
  const [useToken, setUseToken] = useState(false);
  const [forgot, setForgot] = useState(false);
  const [username, setUsername] = useState("");
  const [secret, setSecret] = useState("");
  const [again, setAgain] = useState("");
  const [code, setCode] = useState("");
  const [needCode, setNeedCode] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [busy, setBusy] = useState(false);
  const [waitUntil, setWaitUntil] = useState(0);
  const [now, setNow] = useState(Date.now());

  const secondsLeft = Math.max(0, Math.ceil((waitUntil - now) / 1000));

  // tick once a second only while a wait is running
  useEffect(() => {
    if (!secondsLeft) return undefined;

    const timer = setInterval(() => setNow(Date.now()), 1000);

    return () => clearInterval(timer);
  }, [secondsLeft > 0]); // eslint-disable-line react-hooks/exhaustive-deps

  const check = useCallback(async () => {
    try {
      const status = await whoAmI();

      setAuth(status);
      setNeedLogin((status.required && !status.ok) || status.signup === "first");
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

  // an empty server offers to create its first account straight away
  useEffect(() => {
    if (auth?.signup === "first" && !auth.required) setMode("signup");
  }, [auth]);

  const switchMode = (next) => {
    setMode(next);
    setError("");
    setNotice("");
    setSecret("");
    setAgain("");
    setCode("");
    setNeedCode(false);
    setForgot(false);
  };

  const submit = async (event) => {
    event.preventDefault();
    setBusy(true);
    setError("");

    try {
      if (mode === "signup") {
        if (secret !== again) throw new Error("The two passwords differ.");

        const made = await post("/api/signup", { username, password: secret });

        if (made.pending) {
          setNotice(
            `Request sent for "${made.username}". An administrator has to approve it before you can sign in.`
          );
          setMode("login");
          setSecret("");
          setAgain("");
          setBusy(false);

          return;
        }

        setToken(made.token);
      } else if (useToken) {
        setToken(secret.trim());

        const status = await whoAmI();

        if (!status.ok) {
          setToken("");
          throw new Error("That token was not accepted.");
        }
      } else {
        const body = await post("/api/login", {
          username,
          password: secret,
          ...(needCode && code.trim() ? { code } : {})
        });

        setToken(body.token);
      }

      location.reload();
    } catch (e) {
      if (e.twoFactor) {
        // not a failure: the next step
        setNeedCode(true);
        setNotice("Enter the code from your authenticator app, or one of your recovery codes.");
        setBusy(false);

        return;
      }

      setNotice("");
      setError(e.message);

      if (e.retryAfter) {
        setNow(Date.now());
        setWaitUntil(Date.now() + e.retryAfter * 1000);
      }

      setBusy(false);
    }
  };

  if (!auth) return null;

  if (needLogin) {
    const tokenOnly = !auth.methods?.password && auth.methods?.token;
    const tokenMode = mode === "login" && (useToken || tokenOnly);
    const signupState = auth.signup || "closed";

    const footer =
      mode === "login" && auth.methods?.password && auth.methods?.token ? (
        <button
          type="button"
          className="auth-link"
          onClick={() => {
            setUseToken(!useToken);
            setError("");
          }}
        >
          {useToken ? "Use username and password" : "Use the admin token instead"}
        </button>
      ) : (
        <span>{mode === "login" ? "Sessions end after 12 hours" : "Passwords are stored as salted scrypt hashes"}</span>
      );

    return (
      <AuthShell
        mode={mode}
        onMode={switchMode}
        title={mode === "signup" ? "SIGN UP" : "LOGIN"}
        footer={footer}
      >
        {mode === "signup" && signupState === "closed" ? (
          <div className="auth-form-closed">
            <div className="auth-note">
              Sign-up is closed on this server. Ask an administrator to create an account for you, or to
              allow self-registration under Operations → Users.
            </div>
          </div>
        ) : (
          <form onSubmit={submit}>
            {mode === "signup" && (
              <div className="auth-note">
                {signupState === "first"
                  ? "No account exists yet. The first account becomes the administrator."
                  : "New accounts start as viewers and must be approved by an administrator."}
              </div>
            )}

            {notice && <div className="auth-ok">{notice}</div>}

            {!tokenMode && (
              <AuthField
                icon="user"
                placeholder="Username"
                value={username}
                onChange={setUsername}
                autoComplete="username"
                autoFocus
              />
            )}

            <AuthField
              icon={tokenMode ? "key" : "lock"}
              type="password"
              placeholder={tokenMode ? "Admin token" : "Password"}
              value={secret}
              onChange={setSecret}
              autoComplete={mode === "signup" ? "new-password" : tokenMode ? "off" : "current-password"}
              autoFocus={tokenMode}
            />

            {needCode && mode === "login" && !tokenMode && (
              <AuthField
                icon="key"
                placeholder="Authentication code or recovery code"
                value={code}
                onChange={setCode}
                autoComplete="one-time-code"
                autoFocus
              />
            )}

            {mode === "signup" && (
              <AuthField
                icon="lock"
                type="password"
                placeholder="Repeat password"
                value={again}
                onChange={setAgain}
                autoComplete="new-password"
              />
            )}

            {forgot && (
              <div className="auth-note">
                Passwords cannot be e-mailed from here. Ask an administrator to reset yours under
                Operations → Users, or run <code>python manage_users.py passwd NAME</code> on the server.
              </div>
            )}

            {error && (
              <div className="auth-error" role="alert">
                {error}
              </div>
            )}

            {secondsLeft > 0 && (
              <div className="auth-note" role="status">
                Sign-in is paused to protect the account. You can try again in{" "}
                <b>
                  {Math.floor(secondsLeft / 60)}:{String(secondsLeft % 60).padStart(2, "0")}
                </b>
                .
              </div>
            )}

            <div className="auth-row">
              {mode === "login" && !tokenMode ? (
                <button type="button" className="auth-link" onClick={() => setForgot(!forgot)}>
                  Forgot password?
                </button>
              ) : (
                <span />
              )}

              <button
                className="auth-go"
                type="submit"
                disabled={
                  busy ||
                  (secondsLeft > 0 && mode === "login") ||
                  !secret.trim() ||
                  (!tokenMode && !username.trim()) ||
                  (mode === "signup" && !again) ||
                  (needCode && !code.trim())
                }
              >
                {busy ? "…" : mode === "signup" ? "CREATE" : "LOGIN"}
              </button>
            </div>
          </form>
        )}
      </AuthShell>
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
