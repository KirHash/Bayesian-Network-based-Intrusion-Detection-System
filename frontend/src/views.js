/** Saved alert filters ("views"), kept in this browser. */
const KEY = "ids_views";

export const PRESETS = [
  { name: "Needs attention: open and Critical", status: "open", risk: "Critical", type: "all", query: "" },
  { name: "Open and High risk", status: "open", risk: "High", type: "all", query: "" },
  { name: "Unfamiliar traffic (open anomalies)", status: "open", risk: "all", type: "Anomaly", query: "" },
  { name: "Resolved", status: "resolved", risk: "all", type: "all", query: "" }
];

const FIELDS = ["status", "risk", "type", "query"];

/** Only the fields a view may hold, with text of a sane length. */
function clean(view) {
  return {
    name: String(view.name || "").trim().slice(0, 60),
    status: String(view.status || "open").slice(0, 30),
    risk: String(view.risk || "all").slice(0, 30),
    type: String(view.type || "all").slice(0, 40),
    query: String(view.query || "").slice(0, 100)
  };
}

export function loadViews() {
  try {
    const stored = JSON.parse(localStorage.getItem(KEY) || "[]");

    return Array.isArray(stored) ? stored.map(clean).filter((v) => v.name) : [];
  } catch {
    return [];
  }
}

function store(views) {
  try {
    localStorage.setItem(KEY, JSON.stringify(views));
  } catch {
    /* storage unavailable: the view lasts until reload */
  }

  return views;
}

/** Add a view, or replace the one with the same name. Returns the new list. */
export function saveView(view) {
  const next = clean(view);

  if (!next.name) return loadViews();

  return store([...loadViews().filter((v) => v.name !== next.name), next].sort((a, b) => a.name.localeCompare(b.name)));
}

export function deleteView(name) {
  return store(loadViews().filter((v) => v.name !== name));
}

export const sameFilters = (a, b) => FIELDS.every((field) => (a[field] ?? "") === (b[field] ?? ""));
