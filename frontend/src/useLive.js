import { useEffect, useRef, useState } from "react";

import { send, unauthorized } from "./api.js";
import { wsUrl } from "./config.js";

const MAX_TICKS = 360;

/**
 * Live feed from the FastAPI websocket: per-second ticks for the
 * timeline, drift reports per source, the replay settings, and a
 * `revision` counter that goes up whenever something changed server
 * side so other views know to refetch. Reconnects on drop.
 */
export default function useLive() {
  const [connected, setConnected] = useState(false);
  const [ticks, setTicks] = useState([]);
  const [drift, setDrift] = useState({});
  const [replay, setReplay] = useState({ running: false, rate: 50 });
  const [revision, setRevision] = useState(0);
  const [lastBatch, setLastBatch] = useState(null);
  const [capture, setCapture] = useState(null);
  const [job, setJob] = useState(null);
  const socket = useRef(null);

  useEffect(() => {
    let closed = false;
    let retry;

    const bump = () => setRevision((r) => r + 1);

    const connect = async () => {
      // the feed opens with a one-time ticket, never with the session token itself (an address
      // ends up in logs and browser history)
      let ticket = "";

      try {
        ticket = (await send("/api/ws-ticket", "POST")).ticket;
      } catch {
        if (!closed) retry = setTimeout(connect, 2000);

        return;
      }

      if (closed) return;

      const ws = new WebSocket(wsUrl(`/ws?ticket=${encodeURIComponent(ticket)}`));
      socket.current = ws;

      ws.onopen = () => {
        setConnected(true);
        bump();
      };

      ws.onclose = (event) => {
        setConnected(false);

        // 1008: the server refused the token
        if (event.code === 1008) return unauthorized();

        if (!closed) retry = setTimeout(connect, 2000);
      };

      ws.onmessage = (event) => {
        const msg = JSON.parse(event.data);

        if (msg.type === "hello") {
          setTicks(msg.ticks);
          setDrift(msg.drift);
          setReplay(msg.replay);
          setCapture(msg.capture);
        } else if (msg.type === "capture") {
          setCapture(msg.capture);
          bump();
        } else if (
          msg.type === "ingest_changed" ||
          msg.type === "model_changed" ||
          msg.type === "files_changed"
        ) {
          bump();
        } else if (msg.type === "job") {
          setJob(msg.job);
          bump();
        } else if (msg.type === "batch") {
          setTicks((t) => [...t, msg.tick].slice(-MAX_TICKS));
          setDrift((d) => ({ ...d, [msg.source]: msg.drift }));
          setLastBatch(msg);
          bump();
        } else if (msg.type === "replay") {
          setReplay(msg.replay);
        } else if (msg.type === "alert_updated") {
          bump();
        } else if (msg.type === "reset") {
          setTicks((t) => t.filter((tick) => tick.source !== msg.source));
          setDrift((d) => {
            const rest = { ...d };
            delete rest[msg.source];
            return rest;
          });
          bump();
        }
      };
    };

    connect();

    return () => {
      closed = true;
      clearTimeout(retry);
      socket.current?.close();
    };
  }, []);

  return { connected, ticks, drift, replay, revision, lastBatch, capture, job };
}

/** Re-run `load` when `deps` change or the live revision moves, at most every `every` ms. */
export function useRefresh(load, deps, revision, every = 2000) {
  const last = useRef(0);
  const timer = useRef(null);
  const loader = useRef(load);

  loader.current = load;

  useEffect(() => {
    // changed filters load at once; live revisions are throttled
    clearTimeout(timer.current);
    loader.current();
    last.current = Date.now();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);

  useEffect(() => {
    const wait = Math.max(0, every - (Date.now() - last.current));
    clearTimeout(timer.current);
    timer.current = setTimeout(() => {
      last.current = Date.now();
      loader.current();
    }, wait);
    return () => clearTimeout(timer.current);
  }, [revision, every]);
}
