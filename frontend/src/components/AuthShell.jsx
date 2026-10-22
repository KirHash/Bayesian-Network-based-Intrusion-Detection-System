import Icon from "./Icons.jsx";

/** The product mark in the sign-in colours: a shield around a small network. */
function Logo() {
  return (
    <svg className="auth-logo" width="84" height="84" viewBox="0 0 64 64" aria-hidden="true">
      <path
        d="M32 5 9 14v16c0 13 9 22 23 29 14-7 23-16 23-29V14z"
        fill="none"
        stroke="#4a8ad6"
        strokeWidth="2.6"
        strokeLinejoin="round"
      />
      <g stroke="#4a8ad6" strokeWidth="2" strokeLinecap="round" fill="none">
        <path d="M32 22 43 40H21z" />
        <path d="M32 22v10M21 40l11-8 11 8" opacity=".55" />
      </g>
      <g fill="#131217" stroke="#4a8ad6" strokeWidth="2">
        <circle cx="32" cy="22" r="3.4" />
        <circle cx="43" cy="40" r="3.4" />
        <circle cx="21" cy="40" r="3.4" />
      </g>
    </svg>
  );
}

/** A quiet network map: nodes, links and a few packets travelling along them. */
function NetworkArt() {
  const nodes = [
    [40, 70], [120, 40], [200, 95], [70, 160], [150, 175], [225, 215],
    [60, 260], [140, 290], [210, 330], [90, 370], [170, 410], [40, 330]
  ];

  const links = [
    [0, 1], [1, 2], [0, 3], [1, 4], [2, 4], [3, 4], [2, 5], [4, 5], [3, 6],
    [4, 7], [5, 8], [6, 7], [7, 8], [7, 9], [8, 10], [9, 10], [6, 11], [11, 9]
  ];

  return (
    <svg className="auth-art" viewBox="0 0 260 450" preserveAspectRatio="xMidYMid slice" aria-hidden="true">
      <g stroke="#4a8ad6" strokeOpacity=".35" strokeWidth="1">
        {links.map(([a, b]) => (
          <line key={`${a}-${b}`} x1={nodes[a][0]} y1={nodes[a][1]} x2={nodes[b][0]} y2={nodes[b][1]} />
        ))}
      </g>

      {links.slice(0, 9).map(([a, b], i) => (
        <circle key={`p${a}-${b}`} r="2.4" fill="#f2f2f3" className="packet">
          <animateMotion
            dur={`${3 + (i % 4)}s`}
            begin={`${(i * 0.7).toFixed(1)}s`}
            repeatCount="indefinite"
            path={`M${nodes[a][0]},${nodes[a][1]} L${nodes[b][0]},${nodes[b][1]}`}
          />
        </circle>
      ))}

      {nodes.map(([x, y], i) => (
        <g key={i}>
          <circle cx={x} cy={y} r="3.6" fill="#171719" stroke="#4a8ad6" strokeWidth="1.4" />
        </g>
      ))}

    </svg>
  );
}

/** One underlined field with an icon in front. */
export function AuthField({ icon, type = "text", placeholder, value, onChange, autoComplete, autoFocus, name }) {
  return (
    <label className="auth-field">
      <Icon name={icon} size={18} />
      <input
        name={name}
        type={type}
        placeholder={placeholder}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        autoComplete={autoComplete}
        autoFocus={autoFocus}
        spellCheck={false}
      />
    </label>
  );
}

/**
 * The sign-in surface: a network map and the LOGIN / SIGN UP tabs on one side, the form on the
 * other. Used for signing in, for creating an account and while the server is being found.
 */
export default function AuthShell({ mode, onMode, signupDisabled, title, children, footer }) {
  return (
    <div className="auth-stage">
      <div className="auth-card">
        <aside className="auth-side">
          <NetworkArt />

          <div className="auth-tabs" role="tablist">
            <button
              role="tab"
              aria-selected={mode === "login"}
              className={mode === "login" ? "auth-tab active" : "auth-tab"}
              onClick={() => onMode("login")}
            >
              LOGIN
            </button>

            <button
              role="tab"
              aria-selected={mode === "signup"}
              className={mode === "signup" ? "auth-tab active" : "auth-tab"}
              onClick={() => onMode("signup")}
              disabled={signupDisabled}
              title={signupDisabled ? "Available once the server is connected" : undefined}
            >
              SIGN UP
            </button>
          </div>

          <div className="auth-sidenote">
            <span className="pulse on" /> sensor online
          </div>
        </aside>

        <section className="auth-main">
          <Logo />

          <h1 className="auth-title">{title}</h1>

          <div className="auth-body">{children}</div>

          <footer className="auth-foot">
            <span className="auth-secure">
              <Icon name="shieldcheck" size={16} /> Encrypted session
            </span>

            {footer}
          </footer>
        </section>
      </div>
    </div>
  );
}
