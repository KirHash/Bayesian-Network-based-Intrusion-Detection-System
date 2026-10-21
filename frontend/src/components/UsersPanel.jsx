import { useEffect, useState } from "react";

import { getJSON, send } from "../api.js";
import { useAuth } from "../auth.js";

const ROLES = ["viewer", "analyst", "admin"];

const ROLE_HELP = {
  viewer: "look only",
  analyst: "handle alerts",
  admin: "everything, incl. capture and users"
};

/** Admin-only account management. */
export default function UsersPanel() {
  const { user: me, open } = useAuth();
  const [users, setUsers] = useState([]);
  const [error, setError] = useState("");
  const [form, setForm] = useState({ username: "", password: "", role: "viewer" });

  const load = () =>
    getJSON("/api/users")
      .then(setUsers)
      .catch(() => {});

  useEffect(() => {
    load();
  }, []);

  const act = async (fn) => {
    setError("");

    try {
      await fn();
      await load();
    } catch (e) {
      setError(e.message);
    }
  };

  const add = (event) => {
    event.preventDefault();

    act(async () => {
      await send("/api/users", "POST", form);

      const first = users.length === 0;

      setForm({ username: "", password: "", role: "viewer" });

      // the first account switches sign-in on for everyone
      if (first) location.reload();
    });
  };

  const change = (name, body) =>
    act(() => send(`/api/users/${encodeURIComponent(name)}`, "PATCH", body));

  const resetPassword = (name) => {
    const password = window.prompt(`New password for ${name} (10+ characters):`);

    if (password) change(name, { password });
  };

  const remove = (name) => {
    if (window.confirm(`Delete the account ${name}?`))
      act(() => send(`/api/users/${encodeURIComponent(name)}`, "DELETE"));
  };

  return (
    <div className="card">
      <div className="card-head">
        <h2>Users</h2>
      </div>

      {open && (
        <div className="small-text muted">
          Sign-in is off: anyone who can reach this server is an admin. Creating
          the first account (an admin) turns it on. You can also run{" "}
          <code>python manage_users.py add NAME --role admin</code>.
        </div>
      )}

      <div className="users">
        {users.map((u) => (
          <div key={u.username} className={u.disabled ? "user dim" : "user"}>
            <div className="user-head">
              <span>
                <b>{u.username}</b>
                {u.username === me && <span className="muted"> (you)</span>}
                {!!u.disabled && <span className="muted"> · disabled</span>}
              </span>

              <select
                value={u.role}
                onChange={(e) => change(u.username, { role: e.target.value })}
                title={ROLE_HELP[u.role]}
              >
                {ROLES.map((r) => (
                  <option key={r} value={r}>
                    {r}
                  </option>
                ))}
              </select>
            </div>

            <div className="user-foot muted small-text">
              <span>
                {u.last_login
                  ? `last login ${u.last_login.slice(0, 16).replace("T", " ")}`
                  : "never signed in"}
              </span>

              <span className="actions">
                <button className="link" onClick={() => resetPassword(u.username)}>
                  password
                </button>
                {u.username !== me && (
                  <>
                    <button
                      className="link"
                      onClick={() => change(u.username, { disabled: !u.disabled })}
                    >
                      {u.disabled ? "enable" : "disable"}
                    </button>
                    <button
                      className="link danger-text"
                      onClick={() => remove(u.username)}
                    >
                      delete
                    </button>
                  </>
                )}
              </span>
            </div>
          </div>
        ))}
      </div>

      {error && <div className="error">{error}</div>}

      <form className="add-user" onSubmit={add}>
        <input
          placeholder="username"
          autoComplete="off"
          value={form.username}
          onChange={(e) => setForm({ ...form, username: e.target.value })}
        />
        <input
          type="password"
          placeholder="password (10+ characters)"
          autoComplete="new-password"
          value={form.password}
          onChange={(e) => setForm({ ...form, password: e.target.value })}
        />
        <select
          value={form.role}
          onChange={(e) => setForm({ ...form, role: e.target.value })}
        >
          {ROLES.map((r) => (
            <option key={r} value={r}>
              {r}
            </option>
          ))}
        </select>
        <button className="btn small primary" disabled={!form.username || !form.password}>
          Add user
        </button>
      </form>
    </div>
  );
}
