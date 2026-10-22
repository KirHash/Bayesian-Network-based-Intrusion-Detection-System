import { useCallback, useEffect, useRef, useState } from "react";

import { getToken, setToken } from "../api.js";
import {
  apiUrl,
  getApiBase,
  getDiscoveryName,
  offeredBackend,
  offeredName,
  setApiBase,
  setDiscoveryName,
  validBackend
} from "../config.js";
import { discover, validName } from "../discovery.js";
import AuthShell, { AuthField } from "./AuthShell.jsx";

/** Is something that speaks this API answering at the current backend address? */
async function reachable() {
  try {
    // a name that cannot be looked up can hang for a long time: give up quickly and retry
    const response = await fetch(apiUrl("/api/auth"), {
      headers: getToken() ? { Authorization: `Bearer ${getToken()}` } : {},
      signal: AbortSignal.timeout(6000)
    });

    const body = await response.json();

    return typeof body === "object" && body !== null && "required" in body;
  } catch {
    return false;
  }
}

function leaveQuery() {
  const params = new URLSearchParams(location.search);

  params.delete("api");
  params.delete("name");

  const rest = params.toString();

  history.replaceState(null, "", location.pathname + (rest ? `?${rest}` : "") + location.hash);
}

/**
 * Makes sure the page is talking to a server before the sign-in page appears.
 *
 * Normally this is invisible: the address is remembered, and when it stops answering (the
 * server's tunnel gets a new address on every start) the page looks the new one up through
 * the server owner's DuckDNS name (see discovery.js) and carries on. A link carrying
 * ?api=<address>&name=<name> is only an offer: nothing is sent there until the person
 * confirms it, because a link could come from anyone.
 */
export default function ConnectGate({ children }) {
  const [offer, setOffer] = useState(() => {
    const api = offeredBackend();
    const name = validName(offeredName());

    if (!api && !name) return null;

    return api !== getApiBase() || (name && name !== getDiscoveryName()) ? { api, name } : null;
  });

  const [state, setState] = useState("probing");
  const [looking, setLooking] = useState(false);
  const [typed, setTyped] = useState("");
  const [error, setError] = useState("");
  const state_ = useRef(state);
  const [pending, setPending] = useState(null);
  const [shell, setShell] = useState({ username: "", password: "" });
  const [since] = useState(() => Date.now());
  const [, tick] = useState(0);

  state_.current = state;

  // sign in for the person as soon as the server is reachable, so they only ever see a login page
  useEffect(() => {
    if (state !== "ok" || !pending) return;

    (async () => {
      try {
        const response = await fetch(apiUrl("/api/login"), {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(pending)
        });

        const body = await response.json().catch(() => ({}));

        // this account uses two-factor sign-in: the regular sign-in page takes the code
        if (body.two_factor) return setPending(null);

        if (response.status === 429) throw new Error("Too many failed attempts. Try again in a few minutes.");
        if (!response.ok) throw new Error(body.detail || "Sign-in failed.");

        setToken(body.token);
        setPending(null);
        location.reload();
      } catch (e) {
        setPending(null);
        setError(e.message);
      }
    })();
  }, [state, pending]);

  useEffect(() => {
    const timer = setInterval(() => tick((n) => n + 1), 5000);

    return () => clearInterval(timer);
  }, []);

  const attempt = useCallback(async () => {
    if (await reachable()) return setState("ok");

    // the remembered address is dead: ask DNS where the server is now
    const name = getDiscoveryName();

    if (name) {
      setLooking(true);

      const found = await discover(name);

      setLooking(false);

      // same server, new address: the sign-in token is still good, so keep it
      if (found && found !== getApiBase()) {
        setApiBase(found);

        if (await reachable()) return setState("ok");
      }
    }

    setState("down");
  }, []);

  useEffect(() => {
    if (offer) return undefined;

    attempt();

    // a computer that is still starting, or a tunnel that is still coming up: keep trying
    const timer = setInterval(() => state_.current !== "ok" && attempt(), 4000);

    return () => clearInterval(timer);
  }, [offer, attempt]);

  const accept = ({ api, name }) => {
    // a different server has different accounts
    if (api && api !== getApiBase()) setToken("");

    if (api) setApiBase(api);
    if (name) setDiscoveryName(name);

    leaveQuery();
    setOffer(null);
    setError("");
    setState("probing");
  };

  const submit = (event) => {
    event.preventDefault();

    const text = typed.trim();

    const api = validBackend(text);
    const name = api ? "" : validName(text);

    if (!api && !name) {
      return setError("Enter the server's DuckDNS name (name.duckdns.org) or its full https:// address.");
    }

    if (name) setApiBase("");

    accept({ api, name });
  };

  if (offer) {
    return (
      <AuthShell mode="login" onMode={() => {}} signupDisabled title="CONNECT?">
        <div className="auth-body-stack">
          <div className="auth-note">
            This link asks the dashboard to use the server below. Continue only if it is yours: you will
            type your password to it.
          </div>

          {offer.api && <code className="auth-code">{offer.api}</code>}
          {offer.name && <code className="auth-code">{offer.name}</code>}

          <div className="auth-row">
            <button
              className="auth-link"
              onClick={() => {
                leaveQuery();
                setOffer(null);
              }}
            >
              Cancel
            </button>

            <button className="auth-go" onClick={() => accept(offer)}>
              CONNECT
            </button>
          </div>
        </div>
      </AuthShell>
    );
  }

  if (state === "ok" && !pending) return children;

  const name = getDiscoveryName();
  const current = getApiBase();

  // nothing remembered yet: the one question this page ever asks
  if (!name && !current) {
    if (state === "probing") return null;

    return (
      <AuthShell mode="login" onMode={() => {}} signupDisabled title="CONNECT">
        <form onSubmit={submit}>
          <div className="auth-note">
            Enter your server's DuckDNS name once (for example myids.duckdns.org). After that this page
            finds it by itself.
          </div>

          <AuthField icon="shieldcheck" placeholder="myids.duckdns.org" value={typed} onChange={setTyped} autoFocus />

          {error && <div className="auth-error">{error}</div>}

          <div className="auth-row">
            <span />
            <button className="auth-go" type="submit" disabled={!typed.trim()}>
              CONNECT
            </button>
          </div>
        </form>
      </AuthShell>
    );
  }

  // the server is being found in the background; the person just signs in
  const waited = Date.now() - since;

  const status = pending
    ? "Signing in as soon as your server answers…"
    : state === "probing"
    ? "Connecting to your server…"
    : waited > 30000 && state === "down"
    ? "Still looking for your server…"
    : looking
    ? "Finding your server…"
    : "Your server is starting up…";

  const forget = () => {
    setApiBase("");
    setDiscoveryName("");
    setToken("");
    location.reload();
  };

  return (
    <AuthShell
      mode="login"
      onMode={() => {}}
      signupDisabled
      title="LOGIN"
      footer={
        <button type="button" className="auth-link" onClick={forget}>
          Use a different server
        </button>
      }
    >
      <form
        onSubmit={(e) => {
          e.preventDefault();
          setError("");
          setPending({ username: shell.username, password: shell.password });
        }}
      >
        <div className="auth-note">{status}</div>

        <AuthField
          icon="user"
          placeholder="Username"
          value={shell.username}
          onChange={(v) => setShell({ ...shell, username: v })}
          autoComplete="username"
          autoFocus
        />

        <AuthField
          icon="lock"
          type="password"
          placeholder="Password"
          value={shell.password}
          onChange={(v) => setShell({ ...shell, password: v })}
          autoComplete="current-password"
        />

        {error && <div className="auth-error">{error}</div>}

        {state !== "ok" && waited > 30000 && (
          <div className="auth-note">
            The server runs on your computer, so it must be on with the launcher running. If it is, and this
            keeps going, this device may not be able to look up the tunnel's name: turn on secure DNS in the
            browser's settings, or try another network.
          </div>
        )}

        <div className="auth-row">
          <span />
          <button className="auth-go" disabled={!!pending || !shell.username || !shell.password}>
            {pending ? "WAITING…" : "LOGIN"}
          </button>
        </div>
      </form>
    </AuthShell>
  );
}

/** Which server this page is using, with a way to switch (shown only for a remote one). */
export function ServerNote() {
  const base = getApiBase();

  if (!base) return null;

  return (
    <div className="muted small-text" style={{ textAlign: "center", padding: "16px" }}>
      Server: {new URL(base).host} ·{" "}
      <a
        href="#change-server"
        onClick={(e) => {
          e.preventDefault();
          setApiBase("");
          setDiscoveryName("");
          setToken("");
          location.reload();
        }}
      >
        change
      </a>
    </div>
  );
}
