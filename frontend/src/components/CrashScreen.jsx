import { Component } from "react";

/** The last safety net: if the whole dashboard fails to draw, say so plainly and offer a way out. */
export default class CrashScreen extends Component {
  state = { failed: null };

  static getDerivedStateFromError(error) {
    return { failed: error };
  }

  componentDidCatch(error, info) {
    // the browser console keeps the details for whoever helps
    console.error("dashboard crashed", error, info?.componentStack);
  }

  render() {
    const { failed } = this.state;

    if (!failed) return this.props.children;

    return (
      <main className="crash" role="alert">
        <h1>The dashboard hit a problem</h1>

        <p>
          Nothing was lost: your alerts and settings are stored on the server. Reloading usually fixes it. If it
          keeps happening after a reload, sign out and in again, or ask an administrator to check the server's
          logs (Operations, Logs).
        </p>

        <div className="crash-actions">
          <button className="btn primary" onClick={() => location.reload()}>
            Reload
          </button>

          <button
            className="btn"
            onClick={() => {
              try {
                localStorage.removeItem("ids_token");
              } catch {
                /* storage unavailable */
              }

              location.reload();
            }}
          >
            Sign out and reload
          </button>
        </div>

        <details>
          <summary>Technical details</summary>
          <code>{String(failed?.message || failed)}</code>
        </details>
      </main>
    );
  }
}
