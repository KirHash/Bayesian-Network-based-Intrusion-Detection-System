import { Component } from "react";

/** A panel that fails to draw shows a note instead of taking the whole page down. */
export default class Guard extends Component {
  state = { failed: null };

  static getDerivedStateFromError(error) {
    return { failed: error };
  }

  render() {
    if (!this.state.failed) return this.props.children;

    return (
      <div className="card">
        <h2>{this.props.name}</h2>
        <div className="error">
          This panel could not be drawn ({String(this.state.failed.message || this.state.failed)}).
          The server may be running an older version: restart it, then reload this page.
        </div>
      </div>
    );
  }
}
