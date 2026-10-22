import { act, render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import useLive from "../src/useLive.js";
import { api } from "./helpers.js";

class FakeSocket {
  static all = [];

  constructor(url) {
    this.url = url;
    FakeSocket.all.push(this);
  }

  close() {
    this.closed = true;
  }

  emit(message) {
    this.onmessage({ data: JSON.stringify(message) });
  }
}

function Probe() {
  const live = useLive();

  return (
    <div>
      <span>{live.connected ? "live" : "offline"}</span>
      <span data-testid="ticks">{live.ticks.length}</span>
      <span data-testid="revision">{live.revision}</span>
      <span data-testid="rate">{live.replay.rate}</span>
    </div>
  );
}

describe("the live feed", () => {
  it("opens with a one-time ticket and never with the session token", async () => {
    FakeSocket.all = [];

    vi.stubGlobal("WebSocket", FakeSocket);

    localStorage.setItem("ids_token", "SESSION-TOKEN-VALUE");

    const { calls } = api({ "POST /api/ws-ticket": { ticket: "one-time-ticket", valid_seconds: 30 } });

    render(<Probe />);

    await waitFor(() => expect(FakeSocket.all).toHaveLength(1));

    const url = FakeSocket.all[0].url;

    expect(url).toBe("ws://localhost:3000/ws?ticket=one-time-ticket");
    expect(url).not.toContain("SESSION-TOKEN-VALUE");
    expect(url).not.toContain("token=");

    // the ticket was requested with the token as a header, not in the address
    expect(calls[0].headers.Authorization).toBe("Bearer SESSION-TOKEN-VALUE");
  });

  it("follows what the server sends", async () => {
    FakeSocket.all = [];

    vi.stubGlobal("WebSocket", FakeSocket);

    api({ "POST /api/ws-ticket": { ticket: "t" } });

    render(<Probe />);

    await waitFor(() => expect(FakeSocket.all).toHaveLength(1));

    const socket = FakeSocket.all[0];

    act(() => socket.onopen());

    expect(await screen.findByText("live")).toBeTruthy();

    act(() =>
      socket.emit({
        type: "hello",
        ticks: [{ t: "10:00:00", flows: 5, alerts: 1, source: "replay" }],
        drift: {},
        replay: { running: true, rate: 200 },
        capture: null
      })
    );

    expect(screen.getByTestId("ticks").textContent).toBe("1");
    expect(screen.getByTestId("rate").textContent).toBe("200");

    const before = Number(screen.getByTestId("revision").textContent);

    act(() =>
      socket.emit({
        type: "batch",
        source: "replay",
        tick: { t: "10:00:01", flows: 50, alerts: 4, source: "replay" },
        alerts: [],
        drift: {}
      })
    );

    expect(screen.getByTestId("ticks").textContent).toBe("2");
    expect(Number(screen.getByTestId("revision").textContent)).toBeGreaterThan(before);
  });

  it("goes back to the sign-in page when the server refuses the ticket", async () => {
    FakeSocket.all = [];

    vi.stubGlobal("WebSocket", FakeSocket);

    api({ "POST /api/ws-ticket": { ticket: "t" } });

    const heard = vi.fn();

    window.addEventListener("ids-unauthorized", heard);

    render(<Probe />);

    await waitFor(() => expect(FakeSocket.all).toHaveLength(1));

    act(() => FakeSocket.all[0].onclose({ code: 1008 }));

    window.removeEventListener("ids-unauthorized", heard);

    expect(heard).toHaveBeenCalledOnce();

    // and it does not hammer the server with new connections
    expect(FakeSocket.all).toHaveLength(1);
  });

  it("opens no socket when it cannot get a ticket, and keeps trying", async () => {
    FakeSocket.all = [];

    vi.stubGlobal("WebSocket", FakeSocket);

    let allowed = false;

    const { calls } = api({
      "POST /api/ws-ticket": () => {
        if (!allowed) throw new TypeError("server down");

        return { ticket: "later" };
      }
    });

    vi.useFakeTimers({ toFake: ["setTimeout"] });

    render(<Probe />);

    await vi.advanceTimersByTimeAsync(0);

    expect(FakeSocket.all).toHaveLength(0);

    allowed = true;

    await vi.advanceTimersByTimeAsync(2100);

    vi.useRealTimers();

    await waitFor(() => expect(FakeSocket.all).toHaveLength(1));

    expect(FakeSocket.all[0].url).toContain("ticket=later");
    expect(calls.length).toBeGreaterThanOrEqual(2);
  });
});
