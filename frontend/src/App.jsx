import { useCallback, useEffect, useRef, useState } from "react";

import { getJSON, getToken, send, setToken } from "./api.js";
import { useAuth } from "./auth.js";
import useLive, { useRefresh } from "./useLive.js";
import { ServerNote } from "./components/ConnectGate.jsx";
import AccountPanel from "./components/AccountPanel.jsx";
import DriftPage from "./components/DriftPage.jsx";
import Overview from "./components/Overview.jsx";
import Sidebar from "./components/Sidebar.jsx";
import Topbar from "./components/Topbar.jsx";
import AlertTable from "./components/AlertTable.jsx";
import FlowsTable from "./components/FlowsTable.jsx";
import Operations from "./components/Operations.jsx";
import AlertDrawer from "./components/AlertDrawer.jsx";

const initialAlert = () => {
  const id = Number(new URLSearchParams(location.search).get("alert"));
  return Number.isInteger(id) && id > 0 ? id : null;
};

export default function App() {
  const live = useLive();
  const auth = useAuth();
  const [source, setSource] = useState("all");
  const [selected, setSelected] = useState(initialAlert);
  const [model, setModel] = useState(null);
  const [stats, setStats] = useState(null);
  const [browserAlerts, setBrowserAlerts] = useState(false);
  const PAGES = ["overview", "alerts", "flows", "drift", "account", "operations"];

  const startPage = () => {
    const fromHash = location.hash.slice(1);

    if (fromHash === "operations") return auth.isAdmin ? "operations" : "overview";

    if (PAGES.includes(fromHash)) return fromHash;

    const query = new URLSearchParams(location.search);

    if (query.get("alert")) return "alerts";

    return query.get("view") === "flows" ? "flows" : "overview";
  };

  const [page, setPage] = useState(startPage);

  // the browser's back/forward buttons and links to #operations, #account... follow the address
  useEffect(() => {
    const follow = () => setPage(startPage());

    window.addEventListener("hashchange", follow);

    return () => window.removeEventListener("hashchange", follow);
  });

  const goTo = (next) => {
    setPage(next);
    history.replaceState(null, "", next === "overview" ? location.pathname + location.search : `#${next}`);
  };

  useEffect(() => {
    getJSON("/api/model").then(setModel).catch(() => {});
  }, [live.connected]);

  useRefresh(
    () =>
      getJSON(`/api/stats?source=${source}`)
        .then(setStats)
        .catch(() => {}),
    [source],
    live.revision
  );

  // Browser notification for Critical alerts that arrive while the tab is open
  const notified = useRef(null);

  useEffect(() => {
    const batch = live.lastBatch;

    if (!browserAlerts || !batch || batch === notified.current) return;
    if (batch.source === "replay") return;
    if (source !== "all" && batch.source !== source) return;

    notified.current = batch;

    const critical = batch.alerts.filter((a) => a.risk === "Critical");

    if (critical.length) {
      new Notification(`IDS: ${critical.length} Critical alert(s)`, {
        body: `${critical[0].attack_type} from ${critical[0].src_ip || "unknown"}`,
        tag: "ids-critical"
      });
    }
  }, [live.lastBatch, browserAlerts, source]);

  const close = useCallback(() => setSelected(null), []);

  // errors (e.g. "demo data not found") are shown by the header
  const setReplay = (settings) => send("/api/replay", "POST", settings);

  const signOut = async () => {
    // ends the session on the server; an admin token has nothing to end
    await send("/api/logout", "POST").catch(() => {});

    setToken("");
    location.reload();
  };

  const types = Object.keys(stats?.by_type || {}).sort();

  const waiting = (stats?.by_status?.new || 0) + (stats?.by_status?.investigating || 0);

  return (
    <div className="shell">
      <Sidebar
        page={page}
        onPage={goTo}
        isAdmin={auth.isAdmin}
        connected={live.connected}
        openAlerts={waiting}
      />

      <div className="workspace">
        <Topbar
          page={page}
          model={model}
          source={source}
          onSource={setSource}
          replay={live.replay}
          onReplay={setReplay}
          onReset={() => send("/api/reset", "POST").catch(() => {})}
          user={auth.open ? null : { name: auth.user, role: auth.role }}
          isAdmin={auth.isAdmin}
          onSignOut={getToken() ? signOut : null}
        />

        {model?.trained === false && (
          <div className="warnbox">
            <b>No model has been trained yet</b>, so nothing can be scored.{" "}
            {auth.isAdmin ? (
              <button className="link" onClick={() => goTo("operations")}>
                Open Operations to train one
              </button>
            ) : (
              "Ask an administrator to train one."
            )}
          </div>
        )}

        <main>
          {page === "operations" && auth.isAdmin ? (
            <Operations live={live} />
          ) : page === "account" ? (
            <AccountPanel />
          ) : page === "alerts" ? (
            <AlertTable
              source={source}
              revision={live.revision}
              selected={selected}
              onSelect={setSelected}
              types={types}
              flowsScored={stats?.total || 0}
              onShowFlows={() => goTo("flows")}
            />
          ) : page === "drift" ? (
            <DriftPage drift={live.drift} source={source} revision={live.revision} />
          ) : page === "flows" ? (
            <FlowsTable source={source} revision={live.revision} onSelect={setSelected} />
          ) : (
            <Overview
              live={live}
              stats={stats}
              source={source}
              onOpenAlerts={() => goTo("alerts")}
              onOpenDrift={() => goTo("drift")}
              browserAlerts={browserAlerts}
              onBrowserAlerts={setBrowserAlerts}
            />
          )}
        </main>

        <ServerNote />
      </div>

      <AlertDrawer
        alertId={selected}
        revision={live.revision}
        onClose={close}
      />

    </div>
  );
}
