export const RISK_ORDER = ["Critical", "High", "Medium", "Low"];

export const RISK_COLOR = {
  Critical: "#ff5370",
  High: "#ff9f43",
  Medium: "#f7d154",
  Low: "#4cc38a"
};

export const TYPE_COLOR = {
  DDoS: "#ff5370",
  PortScan: "#4dabf7",
  "Web Attack": "#b197fc",
  Bot: "#ffa94d",
  Anomaly: "#f7d154",
  BENIGN: "#4cc38a"
};

export const STATUS_LABEL = {
  new: "New",
  investigating: "Investigating",
  resolved: "Resolved",
  false_positive: "False positive"
};

export const STATUS_COLOR = {
  new: "#4dabf7",
  investigating: "#f7d154",
  resolved: "#4cc38a",
  false_positive: "#8b95a7"
};

export const SOURCE_LABEL = {
  all: "All sources",
  capture: "Live capture",
  api: "API",
  replay: "Demo replay"
};

export const typeColor = (type) => TYPE_COLOR[type] || "#8b95a7";

export const pct = (value, digits = 1) =>
  value === null || value === undefined
    ? "–"
    : `${(value * 100).toFixed(digits)}%`;

export const num = (value) =>
  value === null || value === undefined ? "–" : value.toLocaleString();
