import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";

import LoginGate from "../src/components/LoginGate.jsx";
import { api, fakeLocation } from "./helpers.js";

const AUTH_REQUIRED = {
  required: true,
  ok: false,
  methods: { password: true, token: false },
  signup: "closed"
};

function mount() {
  return render(
    <LoginGate>
      <div>the dashboard</div>
    </LoginGate>
  );
}

const submit = () => userEvent.click(document.querySelector(".auth-go"));

describe("signing in", () => {
  it("shows the dashboard to someone who is already signed in", async () => {
    api({ "GET /api/auth": { required: true, ok: true, user: "alice", role: "admin", signup: "closed" } });

    mount();

    expect(await screen.findByText("the dashboard")).toBeTruthy();
  });

  it("signs in with a username and password", async () => {
    const { reload } = fakeLocation();

    const { calls } = api({
      "GET /api/auth": AUTH_REQUIRED,
      "POST /api/login": { token: "T1", username: "alice", role: "admin" }
    });

    mount();

    await userEvent.type(await screen.findByPlaceholderText("Username"), "alice");
    await userEvent.type(screen.getByPlaceholderText("Password"), "correct horse battery");
    await submit();

    await waitFor(() => expect(reload).toHaveBeenCalled());

    expect(localStorage.getItem("ids_token")).toBe("T1");
    expect(calls.find((c) => c.path === "/api/login").body).toEqual({
      username: "alice",
      password: "correct horse battery"
    });
  });

  it("shows the server's reason when the password is wrong", async () => {
    api({
      "GET /api/auth": AUTH_REQUIRED,
      "POST /api/login": [401, { detail: "wrong username or password" }]
    });

    mount();

    await userEvent.type(await screen.findByPlaceholderText("Username"), "alice");
    await userEvent.type(screen.getByPlaceholderText("Password"), "nope-nope-nope");
    await submit();

    expect(await screen.findByText("wrong username or password")).toBeTruthy();
    expect(localStorage.getItem("ids_token")).toBeNull();
  });

  it("asks for the authenticator code after the password, then signs in with it", async () => {
    const { reload } = fakeLocation();

    const { calls } = api({
      "GET /api/auth": AUTH_REQUIRED,
      "POST /api/login": ({ body }) =>
        body.code
          ? { token: "T2", username: "alice", role: "admin" }
          : [401, { detail: "enter the code from your authenticator app", two_factor: true }]
    });

    mount();

    await userEvent.type(await screen.findByPlaceholderText("Username"), "alice");
    await userEvent.type(screen.getByPlaceholderText("Password"), "correct horse battery");
    await submit();

    // not an error: the next step
    const code = await screen.findByPlaceholderText("Authentication code or recovery code");

    expect(screen.getByText(/Enter the code from your authenticator app/)).toBeTruthy();
    expect(document.querySelector(".auth-error")).toBeNull();

    // the button waits for a code
    expect(document.querySelector(".auth-go").disabled).toBe(true);

    await userEvent.type(code, "123456");
    await submit();

    await waitFor(() => expect(reload).toHaveBeenCalled());

    const logins = calls.filter((c) => c.path === "/api/login");

    expect(logins).toHaveLength(2);
    expect(logins[0].body.code).toBeUndefined();
    expect(logins[1].body.code).toBe("123456");
    expect(localStorage.getItem("ids_token")).toBe("T2");
  });

  it("keeps asking for a code that is wrong", async () => {
    api({
      "GET /api/auth": AUTH_REQUIRED,
      "POST /api/login": ({ body }) =>
        body.code
          ? [401, { detail: "that code is not right (or was already used)" }]
          : [401, { detail: "enter the code", two_factor: true }]
    });

    mount();

    await userEvent.type(await screen.findByPlaceholderText("Username"), "alice");
    await userEvent.type(screen.getByPlaceholderText("Password"), "correct horse battery");
    await submit();
    await userEvent.type(await screen.findByPlaceholderText("Authentication code or recovery code"), "000000");
    await submit();

    expect(await screen.findByText(/not right/)).toBeTruthy();
    expect(screen.getByPlaceholderText("Authentication code or recovery code")).toBeTruthy();
  });
});

describe("signing up", () => {
  it("offers to create the first account, which becomes the administrator", async () => {
    const { reload } = fakeLocation();

    const { calls } = api({
      "GET /api/auth": { required: false, ok: true, user: "local", role: "admin", signup: "first" },
      "POST /api/signup": { username: "alice", role: "admin", pending: false, token: "T3" }
    });

    mount();

    expect(await screen.findByText(/first account becomes the administrator/)).toBeTruthy();

    await userEvent.type(screen.getByPlaceholderText("Username"), "alice");
    await userEvent.type(screen.getByPlaceholderText("Password"), "correct horse battery");
    await userEvent.type(screen.getByPlaceholderText("Repeat password"), "correct horse battery");
    await submit();

    await waitFor(() => expect(reload).toHaveBeenCalled());

    expect(calls.find((c) => c.path === "/api/signup").body).toEqual({
      username: "alice",
      password: "correct horse battery"
    });
    expect(localStorage.getItem("ids_token")).toBe("T3");
  });

  it("does not send mismatched passwords", async () => {
    const { calls } = api({
      "GET /api/auth": { required: false, ok: true, signup: "first" },
      "POST /api/signup": { token: "x" }
    });

    mount();

    await userEvent.type(await screen.findByPlaceholderText("Username"), "alice");
    await userEvent.type(screen.getByPlaceholderText("Password"), "correct horse battery");
    await userEvent.type(screen.getByPlaceholderText("Repeat password"), "something else entirely");
    await submit();

    expect(await screen.findByText("The two passwords differ.")).toBeTruthy();
    expect(calls.some((c) => c.path === "/api/signup")).toBe(false);
  });

  it("tells a newcomer when the account waits for approval", async () => {
    api({
      "GET /api/auth": { ...AUTH_REQUIRED, signup: "approval" },
      "POST /api/signup": { username: "bob", role: "viewer", pending: true }
    });

    mount();

    await userEvent.click(await screen.findByRole("tab", { name: "SIGN UP" }));
    await userEvent.type(screen.getByPlaceholderText("Username"), "bob");
    await userEvent.type(screen.getByPlaceholderText("Password"), "correct horse battery");
    await userEvent.type(screen.getByPlaceholderText("Repeat password"), "correct horse battery");
    await submit();

    expect(await screen.findByText(/has to approve it/)).toBeTruthy();
    expect(localStorage.getItem("ids_token")).toBeNull();
  });

  it("says so when sign-up is closed", async () => {
    api({ "GET /api/auth": AUTH_REQUIRED });

    mount();

    await userEvent.click(await screen.findByRole("tab", { name: "SIGN UP" }));

    expect(await screen.findByText(/Sign-up is closed on this server/)).toBeTruthy();
    expect(screen.queryByPlaceholderText("Repeat password")).toBeNull();
  });

  it("explains a forgotten password without pretending to send e-mail", async () => {
    api({ "GET /api/auth": AUTH_REQUIRED });

    mount();

    await userEvent.click(await screen.findByText("Forgot password?"));

    expect(await screen.findByText(/cannot be e-mailed/)).toBeTruthy();
  });
});
