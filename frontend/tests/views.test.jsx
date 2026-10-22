import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import AlertViews from "../src/components/AlertViews.jsx";
import { download } from "../src/api.js";
import { PRESETS, deleteView, loadViews, saveView, sameFilters } from "../src/views.js";
import { api } from "./helpers.js";

const NOW = { status: "open", risk: "all", type: "all", query: "" };

describe("saved views", () => {
  it("start empty and keep what is saved, sorted by name", () => {
    expect(loadViews()).toEqual([]);

    saveView({ ...NOW, name: "zebra", risk: "High" });
    saveView({ ...NOW, name: "apple", type: "Bot" });

    expect(loadViews().map((v) => v.name)).toEqual(["apple", "zebra"]);
  });

  it("replace a view of the same name instead of duplicating it", () => {
    saveView({ ...NOW, name: "mine", risk: "High" });
    saveView({ ...NOW, name: "mine", risk: "Critical" });

    expect(loadViews()).toHaveLength(1);
    expect(loadViews()[0].risk).toBe("Critical");
  });

  it("can be deleted", () => {
    saveView({ ...NOW, name: "mine" });

    expect(deleteView("mine")).toEqual([]);
  });

  it("ignore a nameless view, and keep only the fields a view holds", () => {
    saveView({ ...NOW, name: "   " });

    expect(loadViews()).toEqual([]);

    saveView({ ...NOW, name: "x", secret: "should not be kept" });

    expect(Object.keys(loadViews()[0]).sort()).toEqual(["name", "query", "risk", "status", "type"]);
  });

  it("survive junk in storage", () => {
    localStorage.setItem("ids_views", "{not json");

    expect(loadViews()).toEqual([]);

    localStorage.setItem("ids_views", JSON.stringify({ not: "a list" }));

    expect(loadViews()).toEqual([]);
  });

  it("compare filters, not names", () => {
    expect(sameFilters(PRESETS[0], { status: "open", risk: "Critical", type: "all", query: "" })).toBe(true);
    expect(sameFilters(PRESETS[0], { ...PRESETS[0], risk: "High" })).toBe(false);
  });
});

describe("the views bar", () => {
  it("applies a ready-made view", async () => {
    const onApply = vi.fn();

    render(<AlertViews current={NOW} source="all" onApply={onApply} />);

    await userEvent.selectOptions(screen.getByLabelText("Saved views"), PRESETS[2].name);

    expect(onApply).toHaveBeenCalledWith(expect.objectContaining({ status: "open", type: "Anomaly" }));
  });

  it("saves the current filters under a name and offers them afterwards", async () => {
    vi.spyOn(window, "prompt").mockReturnValue("My scans");

    const { rerender } = render(<AlertViews current={{ ...NOW, type: "PortScan", risk: "High" }} source="all" onApply={() => {}} />);

    await userEvent.click(screen.getByRole("button", { name: "Save view…" }));

    expect(loadViews()[0]).toMatchObject({ name: "My scans", type: "PortScan", risk: "High" });

    // it is listed, selected while the filters match, and can be deleted
    rerender(<AlertViews current={{ ...NOW, type: "PortScan", risk: "High" }} source="all" onApply={() => {}} />);

    expect(screen.getByLabelText("Saved views").value).toBe("My scans");

    await userEvent.click(screen.getByRole("button", { name: /Delete/ }));

    expect(loadViews()).toEqual([]);
  });

  it("does not offer to delete a ready-made view", () => {
    render(<AlertViews current={PRESETS[1]} source="all" onApply={() => {}} />);

    expect(screen.getByLabelText("Saved views").value).toBe(PRESETS[1].name);
    expect(screen.queryByRole("button", { name: /Delete/ })).toBeNull();
  });

  it("saves nothing when the name is left empty", async () => {
    vi.spyOn(window, "prompt").mockReturnValue("");

    render(<AlertViews current={NOW} source="all" onApply={() => {}} />);

    await userEvent.click(screen.getByRole("button", { name: "Save view…" }));

    expect(loadViews()).toEqual([]);
  });

  it("exports with the filters on screen and the source filter", async () => {
    const { calls } = api({
      "GET /api/alerts/export": () => [200, "id\n"]
    });

    vi.stubGlobal("URL", Object.assign(URL, { createObjectURL: vi.fn(() => "blob:x"), revokeObjectURL: vi.fn() }));

    // a real browser reads the body as a blob
    const original = globalThis.fetch;

    vi.stubGlobal("fetch", async (...args) => {
      const response = await original(...args);

      return { ...response, headers: new Headers({ "Content-Disposition": 'attachment; filename="alerts-1.csv"' }), blob: async () => new Blob(["id\n"]) };
    });

    localStorage.setItem("ids_token", "T");

    render(<AlertViews current={{ status: "open", risk: "High", type: "Bot", query: " 10.0.0 " }} source="api" onApply={() => {}} />);

    await userEvent.click(screen.getByRole("button", { name: "Export CSV" }));

    await waitFor(() => expect(calls).toHaveLength(1));

    expect(calls[0].path).toBe("/api/alerts/export");
    expect(URL.createObjectURL).toHaveBeenCalled();
  });

  it("says so when the export fails", async () => {
    api({ "GET /api/alerts/export": [500, { detail: "the export broke" }] });

    render(<AlertViews current={NOW} source="all" onApply={() => {}} />);

    await userEvent.click(screen.getByRole("button", { name: "Export CSV" }));

    expect(await screen.findByText("the export broke")).toBeTruthy();
  });
});

describe("download", () => {
  it("names the file after the server's header, sends the token and cleans up", async () => {
    localStorage.setItem("ids_token", "SECRET");

    let seen;

    vi.stubGlobal("fetch", async (url, options) => {
      seen = { url, headers: options.headers };

      return {
        ok: true,
        status: 200,
        headers: new Headers({ "Content-Disposition": 'attachment; filename="alerts-20261022.csv"' }),
        blob: async () => new Blob(["a,b\n1,2\n"])
      };
    });

    vi.stubGlobal("URL", Object.assign(URL, { createObjectURL: vi.fn(() => "blob:abc"), revokeObjectURL: vi.fn() }));

    const clicked = [];

    const realCreate = document.createElement.bind(document);

    vi.spyOn(document, "createElement").mockImplementation((tag) => {
      const element = realCreate(tag);

      if (tag === "a") element.click = () => clicked.push(element.download);

      return element;
    });

    await download("/api/alerts/export?status=open");

    expect(seen.headers.Authorization).toBe("Bearer SECRET");
    expect(clicked).toEqual(["alerts-20261022.csv"]);
    expect(URL.revokeObjectURL).toHaveBeenCalledWith("blob:abc");
    expect(document.querySelector("a[download]")).toBeNull();
  });
});
