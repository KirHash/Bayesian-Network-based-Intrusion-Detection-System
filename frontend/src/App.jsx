import { useCallback, useEffect, useRef, useState } from "react";

import { getJSON, getToken, send, setToken } from "./api.js";
import { useAuth } from "./auth.js";
import useLive, { useRefresh } from "./useLive.js";
import Header from "./components/Header.jsx";
import Kpis from "./components/Kpis.jsx";
import AlertTable from "./components/AlertTable.jsx";
import FlowsTable from "./components/FlowsTable.jsx";
import SourcesCard from "./components/SourcesCard.jsx";
import Operations from "./components/Operations.jsx";
import AlertDrawer from "./components/AlertDrawer.jsx";
import DriftCard from "./components/DriftCard.jsx";
import NotificationsCard from "./components/NotificationsCard.jsx";
import { RiskBars, Timeline, TypeDonut } from "./components/Charts.jsx";

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
  // admins also get an Operations page (#operations), kept across reloads
  const [page, setPage] = useState(() =>
    location.hash === "#operations" && auth.isAdmin ? "operations" : "monitor"
  );

  const goTo = (next) => {
    setPage(next);
    history.replaceState(null, "", next === "operations" ? "#operations" : location.pathname + location.search);
  };

  const [view, setView] = useState(() =>
    new URLSearchParams(location.search).get("view") === "flows" ? "flows" : "alerts"
  );

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

  return (
    <div className="app">
      <Header
        model={model}
        connected={live.connected}
        source={source}
        onSource={setSource}
        replay={live.replay}
        onReplay={setReplay}
        onReset={() => send("/api/reset", "POST").catch(() => {})}
        page={page}
        onPage={goTo}
        user={auth.open ? null : { name: auth.user, role: auth.role }}
        isAdmin={auth.isAdmin}
        onSignOut={getToken() ? signOut : null}
      />

      {model?.trained === false && page === "monitor" && (
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

      {page === "operations" && auth.isAdmin ? (
        <Operations live={live} />
      ) : (
      <>
      <Kpis stats={stats} />

      <div className="grid">
        <div className="card wide">
          <div className="card-head">
            <h2>Traffic per second</h2>
          </div>
          <Timeline ticks={live.ticks} source={source} />
        </div>

        <div className="card">
          <div className="card-head">
            <h2>Alerts by type</h2>
          </div>
          <TypeDonut byType={stats?.by_type} />
        </div>

        <div className="card">
          <div className="card-head">
            <h2>Alerts by risk</h2>
          </div>
          <RiskBars byRisk={stats?.by_risk} />
        </div>
      </div>

      <div className="split">
        <div className="main">
          <div className="tabs">
            <button
              className={view === "alerts" ? "tab active" : "tab"}
              onClick={() => setView("alerts")}
            >
              Alerts
            </button>
            <button
              className={view === "flows" ? "tab active" : "tab"}
              onClick={() => setView("flows")}
            >
              Recent flows
            </button>
          </div>

          {view === "alerts" ? (
            <AlertTable
              source={source}
              revision={live.revision}
              selected={selected}
              onSelect={setSelected}
              types={types}
              flowsScored={stats?.total || 0}
              onShowFlows={() => setView("flows")}
            />
          ) : (
            <FlowsTable
              source={source}
              revision={live.revision}
              onSelect={setSelected}
            />
          )}
        </div>

        <div className="side">
          <SourcesCard revision={live.revision} />
          <DriftCard drift={live.drift} source={source} />
          <NotificationsCard
            browserAlerts={browserAlerts}
            onBrowserAlerts={setBrowserAlerts}
          />
        </div>
      </div>
      </>
      )}

      <AlertDrawer
        alertId={selected}
        revision={live.revision}
        onClose={close}
      />
    </div>
  );
}
