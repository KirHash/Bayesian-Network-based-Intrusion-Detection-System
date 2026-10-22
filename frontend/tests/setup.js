import { cleanup } from "@testing-library/react";
import { afterEach, beforeEach, vi } from "vitest";

// The dashboard remembers things in localStorage and the address; start every test clean.
beforeEach(() => {
  localStorage.clear();
  history.replaceState(null, "", "/");
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

// recharts measures its container with a ResizeObserver, which jsdom does not have
globalThis.ResizeObserver = class {
  observe() {}
  unobserve() {}
  disconnect() {}
};

// jsdom cannot navigate (a download link, an external address); it would print "Not implemented"
const quietNavigation = HTMLAnchorElement.prototype.click;

HTMLAnchorElement.prototype.click = function click() {
  const href = this.getAttribute("href") || "";

  if (this.hasAttribute("download") || /^(blob:|https?:)/.test(href)) return;

  quietNavigation.call(this);
};
