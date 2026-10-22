import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import { SessionsCard, TwoFactorCard } from "../src/components/SecurityCards.jsx";
import { api } from "./helpers.js";

const SECRET = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";
const URI = `otpauth://totp/Bayesian%20IDS:alice?secret=${SECRET}&issuer=Bayesian%20IDS`;
const RECOVERY = ["aaaa-bbbb", "cccc-dddd", "eeee-ffff", "gggg-hhhh", "jjjj-kkkk", "mmmm-nnnn", "pppp-qqqq", "rrrr-ssss"];

describe("setting up two-factor sign-in", () => {
  function server(state = { enabled: false, recovery_left: 0 }) {
    const current = { ...state };

    return api({
      "GET /api/account/two-factor": () => ({ ...current }),
      "POST /api/account/two-factor/start": ({ body }) =>
        body.current_password === "correct horse battery"
          ? { secret: SECRET, uri: URI }
          : [400, { detail: "the current password is wrong" }],
      "POST /api/account/two-factor/confirm": ({ body }) => {
        if (body.code !== "123456") return [400, { detail: "that code is not right" }];

        current.enabled = true;
        current.recovery_left = 8;

        return { recovery_codes: RECOVERY };
      },
      "POST /api/account/two-factor/disable": ({ body }) => {
        if (body.code !== "654321") return [400, { detail: "that code is not right (or was already used)" }];

        current.enabled = false;

        return { enabled: false, recovery_left: 0 };
      }
    });
  }

  it("walks through password, QR code, confirmation and recovery codes", async () => {
    const { calls } = server();

    render(<TwoFactorCard />);

    await userEvent.click(await screen.findByRole("button", { name: "Set up two-factor sign-in" }));

    // the password is asked again first
    await userEvent.type(screen.getByLabelText("Confirm with your password"), "correct horse battery");
    await userEvent.click(screen.getByRole("button", { name: "Continue" }));

    // the QR code is drawn here, and the key can be typed by hand
    await waitFor(() => expect(document.querySelector(".qr svg")).not.toBeNull());

    expect(document.querySelector(".secret").textContent).toBe("JBSW Y3DP EHPK 3PXP JBSW Y3DP EHPK 3PXP");

    const confirm = screen.getByRole("button", { name: "Turn on" });

    // the button waits for a full code
    expect(confirm.disabled).toBe(true);

    await userEvent.type(screen.getByLabelText("2. Enter the 6-digit code the app shows"), "123456");
    await userEvent.click(confirm);

    // the recovery codes are shown, once
    expect(await screen.findByText(/shown only now/)).toBeTruthy();
    expect(document.querySelectorAll(".recovery li")).toHaveLength(8);
    expect(screen.getByText("aaaa-bbbb")).toBeTruthy();

    await userEvent.click(screen.getByRole("button", { name: "I have saved them" }));

    expect(await screen.findByText(/8 recovery codes are left/)).toBeTruthy();
    expect(screen.queryByText("aaaa-bbbb")).toBeNull();

    expect(calls.find((c) => c.path.endsWith("/start")).body).toEqual({ current_password: "correct horse battery" });
    expect(calls.find((c) => c.path.endsWith("/confirm")).body).toEqual({ code: "123456" });
  });

  it("says so when the password is wrong and stays on that step", async () => {
    server();

    render(<TwoFactorCard />);

    await userEvent.click(await screen.findByRole("button", { name: "Set up two-factor sign-in" }));
    await userEvent.type(screen.getByLabelText("Confirm with your password"), "nope-nope-nope");
    await userEvent.click(screen.getByRole("button", { name: "Continue" }));

    expect(await screen.findByText("the current password is wrong")).toBeTruthy();
    expect(document.querySelector(".qr")).toBeNull();
  });

  it("refuses a wrong confirmation code without turning anything on", async () => {
    server();

    render(<TwoFactorCard />);

    await userEvent.click(await screen.findByRole("button", { name: "Set up two-factor sign-in" }));
    await userEvent.type(screen.getByLabelText("Confirm with your password"), "correct horse battery");
    await userEvent.click(screen.getByRole("button", { name: "Continue" }));
    await userEvent.type(await screen.findByLabelText("2. Enter the 6-digit code the app shows"), "000000");
    await userEvent.click(screen.getByRole("button", { name: "Turn on" }));

    expect(await screen.findByText("that code is not right")).toBeTruthy();
    expect(document.querySelector(".recovery")).toBeNull();
  });

  it("can be cancelled part way", async () => {
    server();

    render(<TwoFactorCard />);

    await userEvent.click(await screen.findByRole("button", { name: "Set up two-factor sign-in" }));
    await userEvent.click(screen.getByRole("button", { name: "Cancel" }));

    expect(screen.getByRole("button", { name: "Set up two-factor sign-in" })).toBeTruthy();
  });
});

describe("turning it off", () => {
  it("needs the password and a code", async () => {
    const { calls } = api({
      "GET /api/account/two-factor": { enabled: true, recovery_left: 7 },
      "POST /api/account/two-factor/disable": [400, { detail: "that code is not right (or was already used)" }]
    });

    render(<TwoFactorCard />);

    expect(await screen.findByText(/7 recovery codes are left/)).toBeTruthy();

    await userEvent.click(screen.getByRole("button", { name: "Turn off…" }));

    const submit = screen.getByRole("button", { name: "Turn off two-factor" });

    expect(submit.disabled).toBe(true);

    await userEvent.type(screen.getByLabelText("Your password"), "correct horse battery");
    await userEvent.type(screen.getByLabelText("A code from the app (or a recovery code)"), "000000");
    await userEvent.click(submit);

    expect(await screen.findByText(/not right/)).toBeTruthy();
    expect(calls.find((c) => c.path.endsWith("/disable")).body).toEqual({
      current_password: "correct horse battery",
      code: "000000"
    });
  });
});

describe("the devices signed in", () => {
  const sessions = [
    { id: "aaaaaaaaaaaa", created_at: "2026-10-22T01:00:00", client: "10.0.0.5", current: true },
    { id: "bbbbbbbbbbbb", created_at: "2026-10-21T09:30:00", client: "203.0.113.9", current: false }
  ];

  it("lists them and signs out the others", async () => {
    let listed = sessions;

    api({
      "GET /api/account/sessions": () => listed,
      "POST /api/account/sessions/sign-out-others": () => {
        listed = [sessions[0]];

        return { ended: 1 };
      }
    });

    render(<SessionsCard />);

    expect(await screen.findByText("203.0.113.9")).toBeTruthy();
    expect(screen.getByText("this device")).toBeTruthy();

    await userEvent.click(screen.getByRole("button", { name: "Sign out all other devices" }));

    expect(await screen.findByText("1 other session signed out.")).toBeTruthy();
    await waitFor(() => expect(screen.queryByText("203.0.113.9")).toBeNull());
  });

  it("has nothing to sign out when this is the only device", async () => {
    api({ "GET /api/account/sessions": [sessions[0]] });

    render(<SessionsCard />);

    await screen.findByText("this device");

    expect(screen.getByRole("button", { name: "Sign out all other devices" }).disabled).toBe(true);
  });
});

it("does not break when the clipboard is unavailable", async () => {
  api({
    "GET /api/account/two-factor": { enabled: false, recovery_left: 0 },
    "POST /api/account/two-factor/start": { secret: SECRET, uri: URI },
    "POST /api/account/two-factor/confirm": { recovery_codes: RECOVERY }
  });

  vi.stubGlobal("navigator", { clipboard: { writeText: () => Promise.reject(new Error("denied")) } });

  render(<TwoFactorCard />);

  await userEvent.click(await screen.findByRole("button", { name: "Set up two-factor sign-in" }));
  await userEvent.type(screen.getByLabelText("Confirm with your password"), "correct horse battery");
  await userEvent.click(screen.getByRole("button", { name: "Continue" }));
  await userEvent.type(await screen.findByLabelText("2. Enter the 6-digit code the app shows"), "123456");
  await userEvent.click(screen.getByRole("button", { name: "Turn on" }));
  await userEvent.click(await screen.findByRole("button", { name: "Copy" }));

  // the codes stay on screen to be copied by hand
  expect(screen.getByText("aaaa-bbbb")).toBeTruthy();
});
