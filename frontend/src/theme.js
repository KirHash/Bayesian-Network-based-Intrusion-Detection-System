export const RISK_ORDER = ["Critical", "High", "Medium", "Low"];

// Colour goes on what needs a decision: the risk bands. Attack types are told apart by lightness
// (one neutral ramp, the accent blue on the commonest family), never by a hue each.
export const RISK_COLOR = {
  Critical: "#e5566f",
  High: "#d9a441",
  Medium: "#8a8c92",
  Low: "#44a282"
};

const RAMP = ["#f2f2f3", "#4a8ad6", "#c4c4c8", "#9a9ca2", "#74767c", "#575960"];

export const TYPE_COLOR = {
  DDoS: RAMP[0],
  PortScan: RAMP[1],
  "Web Attack": RAMP[2],
  Bot: RAMP[3],
  Anomaly: RAMP[4],
  "DoS Hulk": RAMP[0],
  "DoS GoldenEye": RAMP[2],
  "DoS slowloris": RAMP[3],
  "DoS Slowhttptest": RAMP[4],
  "FTP-Patator": RAMP[5],
  "SSH-Patator": RAMP[1],
  Infiltration: RAMP[5],
  BENIGN: "#44a282"
};

export const STATUS_LABEL = {
  new: "New",
  investigating: "Investigating",
  resolved: "Resolved",
  false_positive: "False positive"
};

export const STATUS_COLOR = {
  new: "#4a8ad6",
  investigating: "#d9a441",
  resolved: "#44a282",
  false_positive: "#74767c"
};

export const SOURCE_LABEL = {
  all: "All sources",
  capture: "Live capture",
  api: "API",
  replay: "Demo replay"
};

export const typeColor = (type) => TYPE_COLOR[type] || "#8a8c92";

export const pct = (value, digits = 1) =>
  value === null || value === undefined
    ? "–"
    : `${(value * 100).toFixed(digits)}%`;

export const num = (value) =>
  value === null || value === undefined ? "–" : value.toLocaleString();
