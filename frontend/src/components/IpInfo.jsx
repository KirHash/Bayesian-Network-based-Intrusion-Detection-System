import { useState } from "react";

import { getJSON } from "../api.js";
import { ipKind, lookupLinks } from "../ipinfo.js";

const NOTE = {
  private: "inside a private network",
  loopback: "this machine itself",
  "link-local": "automatic local address",
  multicast: "a group address (service discovery and the like)",
  reserved: "not a real host address"
};

/** One address of an alert: what kind it is, its name on request, and where to look it up. */
export default function IpInfo({ address, label }) {
  const [name, setName] = useState(undefined);
  const [busy, setBusy] = useState(false);

  const kind = ipKind(address);

  if (!kind) return null;

  const lookup = async () => {
    setBusy(true);

    try {
      setName((await getJSON(`/api/lookup/${encodeURIComponent(address)}`)).name);
    } catch {
      setName(null);
    }

    setBusy(false);
  };

  return (
    <div className="ipinfo">
      <div>
        <span className="muted small-text">{label}</span> <span className="mono">{address}</span>{" "}
        <span className={`kind ${kind}`}>{kind}</span>
      </div>

      {kind !== "public" ? (
        <div className="muted small-text">{NOTE[kind]}</div>
      ) : (
        <div className="small-text">
          {name === undefined ? (
            <button className="link" onClick={lookup} disabled={busy}>
              {busy ? "looking up…" : "look up its name"}
            </button>
          ) : (
            <span>{name || "no name registered"}</span>
          )}

          <span className="muted">
            {" "}
            · open in{" "}
            {lookupLinks(address).map(([site, url], i) => (
              <span key={site}>
                {i > 0 && ", "}
                <a href={url} target="_blank" rel="noreferrer noopener">
                  {site}
                </a>
              </span>
            ))}
          </span>
        </div>
      )}
    </div>
  );
}
