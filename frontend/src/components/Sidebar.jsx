import { useState } from "react";

import Icon, { Mark } from "./Icons.jsx";

const KEY = "ids_rail";

const remembered = () => {
  try {
    return localStorage.getItem(KEY) !== "0";
  } catch {
    return true;
  }
};

/** The navigation rail: icons by default (a tooltip names each), labels when opened. */
export default function Sidebar({ page, onPage, isAdmin, connected, openAlerts }) {
  const [folded, setFolded] = useState(remembered);

  const toggle = () => {
    setFolded(!folded);

    try {
      localStorage.setItem(KEY, folded ? "0" : "1");
    } catch {
      /* storage unavailable */
    }
  };

  const items = [
    ["overview", "Overview", "overview"],
    ["alerts", "Alerts", "alerts", openAlerts],
    ["flows", "Flows", "flows"],
    ["drift", "Drift", "drift"],
    ["account", "Account", "account"],
    ...(isAdmin ? [["operations", "Operations", "operations"]] : [])
  ];

  return (
    <nav className={`rail ${folded ? "folded" : ""}`} aria-label="Main">
      <div className="rail-brand">
        <Mark />
        <div>
          <b>Bayesian IDS</b>
          <span>Threat console</span>
        </div>
      </div>

      <ul>
        {items.map(([id, label, icon, badge]) => (
          <li key={id}>
            <button
              className={page === id ? "rail-item active" : "rail-item"}
              onClick={() => onPage(id)}
              title={label}
            >
              <Icon name={icon} />
              <span className="rail-label">{label}</span>
              {!!badge && <span className="rail-badge">{badge > 99 ? "99+" : badge}</span>}
            </button>
          </li>
        ))}
      </ul>

      <div className="rail-foot">
        <span className={`pulse ${connected ? "on" : "off"}`} title={connected ? "Live" : "Reconnecting…"} />
        <span>{connected ? "Live feed" : "Reconnecting…"}</span>

        <button className="rail-fold" onClick={toggle} title={folded ? "Expand" : "Collapse"}>
          <Icon name={folded ? "expand" : "collapse"} size={16} />
        </button>
      </div>
    </nav>
  );
}
