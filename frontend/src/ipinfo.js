/** What sort of address this is, decided in the browser (the server's answer agrees; see /api/lookup). */
const v4 = (text) => {
  const parts = text.split(".");

  if (parts.length !== 4 || parts.some((p) => !/^\d{1,3}$/.test(p) || Number(p) > 255)) return null;

  return parts.map(Number);
};

export function ipKind(text) {
  const address = String(text || "").trim();

  const four = v4(address);

  if (four) {
    const [a, b] = four;

    if (a === 127) return "loopback";
    if (a === 169 && b === 254) return "link-local";
    if (a >= 224 && a <= 239) return "multicast";
    if (a === 0 || a >= 240) return "reserved";
    if (a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127)) {
      return "private";
    }

    return "public";
  }

  if (!/^[0-9a-f:]+$/i.test(address) || !address.includes(":")) return null;

  const lower = address.toLowerCase();

  if (lower === "::1") return "loopback";
  if (lower === "::") return "reserved";
  if (/^fe[89ab]/.test(lower)) return "link-local";
  if (/^f[cd]/.test(lower)) return "private";
  if (lower.startsWith("ff")) return "multicast";

  return "public";
}

/** Places to look an address up, for a person to open (nothing is sent from here). */
export const lookupLinks = (address) => [
  ["AbuseIPDB", `https://www.abuseipdb.com/check/${encodeURIComponent(address)}`],
  ["VirusTotal", `https://www.virustotal.com/gui/ip-address/${encodeURIComponent(address)}`],
  ["Shodan", `https://www.shodan.io/host/${encodeURIComponent(address)}`]
];
