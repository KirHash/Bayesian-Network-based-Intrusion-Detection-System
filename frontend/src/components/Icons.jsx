/** Small line icons, drawn for this dashboard (24x24, stroke follows the text colour). */
const PATHS = {
  overview: (
    <>
      <rect x="3.5" y="3.5" width="7" height="9" rx="2" />
      <rect x="13.5" y="3.5" width="7" height="5" rx="2" />
      <rect x="13.5" y="11.5" width="7" height="9" rx="2" />
      <rect x="3.5" y="15.5" width="7" height="5" rx="2" />
    </>
  ),
  alerts: (
    <>
      <path d="M12 3.5 21 19H3z" />
      <path d="M12 10v4.2" />
      <circle cx="12" cy="16.6" r=".6" />
    </>
  ),
  flows: (
    <>
      <path d="M3 8h11a3 3 0 0 0 0-6" />
      <path d="M21 16H10a3 3 0 0 0 0 6" />
      <path d="M3 12h18" />
    </>
  ),
  account: (
    <>
      <circle cx="12" cy="8.5" r="3.6" />
      <path d="M4.5 20c.8-3.6 3.8-5.4 7.5-5.4s6.7 1.8 7.5 5.4" />
    </>
  ),
  operations: (
    <>
      <circle cx="12" cy="12" r="3" />
      <path d="M12 2.8v3M12 18.2v3M2.8 12h3M18.2 12h3M5.5 5.5l2.1 2.1M16.4 16.4l2.1 2.1M18.5 5.5l-2.1 2.1M7.6 16.4l-2.1 2.1" />
    </>
  ),
  signout: (
    <>
      <path d="M9 4H5.5A1.5 1.5 0 0 0 4 5.5v13A1.5 1.5 0 0 0 5.5 20H9" />
      <path d="M15 8l4 4-4 4M19 12H9" />
    </>
  ),
  user: (
    <>
      <circle cx="12" cy="8" r="3.8" />
      <path d="M4.5 20.5c.6-4 3.6-6 7.5-6s6.9 2 7.5 6" />
    </>
  ),
  lock: (
    <>
      <rect x="5" y="10.5" width="14" height="10" rx="2.4" />
      <path d="M8.5 10.5V8a3.5 3.5 0 0 1 7 0v2.5" />
      <circle cx="12" cy="15.5" r="1.2" />
    </>
  ),
  key: (
    <>
      <circle cx="8" cy="14" r="4" />
      <path d="M11 11l8.5-8.5M16 6l2.5 2.5M13.5 8.5 16 11" />
    </>
  ),
  shieldcheck: (
    <>
      <path d="M12 3 4.5 6v5.5c0 4.6 3 8 7.5 9.5 4.5-1.5 7.5-4.9 7.5-9.5V6z" />
      <path d="m8.8 12 2.4 2.4 4.2-4.4" />
    </>
  ),
  drift: (
    <>
      <path d="M3 17c3 0 3-10 6-10s3 10 6 10 3-6 6-6" />
      <path d="M3 21h18" />
    </>
  ),
  collapse: <path d="M14.5 6 8.5 12l6 6" />,
  expand: <path d="M9.5 6l6 6-6 6" />,
  DDoS: (
    <>
      <circle cx="12" cy="12" r="2" />
      <path d="M12 3v4M12 17v4M3 12h4M17 12h4M5.6 5.6l2.8 2.8M15.6 15.6l2.8 2.8M18.4 5.6l-2.8 2.8M8.4 15.6l-2.8 2.8" />
    </>
  ),
  PortScan: (
    <>
      <circle cx="12" cy="12" r="8.5" />
      <circle cx="12" cy="12" r="4.5" />
      <path d="M12 12l5.4-5.4" />
    </>
  ),
  "Web Attack": (
    <>
      <path d="M8.5 7 3.5 12l5 5M15.5 7l5 5-5 5" />
      <path d="M13.6 5.5 10.4 18.5" />
    </>
  ),
  Bot: (
    <>
      <rect x="4.5" y="8" width="15" height="11" rx="3" />
      <path d="M12 8V4.5" />
      <circle cx="12" cy="3.6" r="1" />
      <circle cx="9" cy="13" r="1.1" />
      <circle cx="15" cy="13" r="1.1" />
    </>
  ),
  Anomaly: <path d="M2.5 12h4l2.5-6 4 12 2.5-6h6" />,
  DoS: (
    <>
      <path d="M12 3v11" />
      <path d="m7 10 5 5 5-5" />
      <path d="M4 20h16" />
    </>
  ),
  Patator: (
    <>
      <circle cx="8" cy="14" r="4" />
      <path d="M11 11l8.5-8.5M16 6l2.5 2.5M13.5 8.5 16 11" />
    </>
  ),
  Infiltration: (
    <>
      <path d="M2.5 12S6 5.5 12 5.5 21.5 12 21.5 12 18 18.5 12 18.5 2.5 12 2.5 12z" />
      <circle cx="12" cy="12" r="2.8" />
    </>
  ),
  other: (
    <>
      <path d="M12 3 4 6v6c0 4.4 3.2 7.6 8 9 4.8-1.4 8-4.6 8-9V6z" />
    </>
  )
};

// attack types that share a drawing: every DoS variant, both brute-force services
const SAME_ICON = {
  "DoS Hulk": "DoS",
  "DoS GoldenEye": "DoS",
  "DoS slowloris": "DoS",
  "DoS Slowhttptest": "DoS",
  "FTP-Patator": "Patator",
  "SSH-Patator": "Patator"
};

export default function Icon({ name, size = 20 }) {
  name = SAME_ICON[name] || name;

  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.7"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      {PATHS[name] || PATHS.other}
    </svg>
  );
}

/** The product mark: a shield holding a small network triangle. */
export function Mark({ size = 30 }) {
  return (
    <svg width={size} height={size} viewBox="0 0 32 32" aria-hidden="true">
      <path d="M16 2.5 4.5 7v8.2c0 6.2 4.6 11 11.5 14.3 6.9-3.3 11.5-8.1 11.5-14.3V7z" fill="#4a8ad6" />
      <g stroke="#0d0d10" strokeWidth="1.6" fill="#0d0d10" strokeLinejoin="round">
        <path d="M16 10.5 21.5 20h-11z" fill="none" />
        <circle cx="16" cy="10.5" r="1.9" />
        <circle cx="21.5" cy="20" r="1.9" />
        <circle cx="10.5" cy="20" r="1.9" />
      </g>
    </svg>
  );
}
