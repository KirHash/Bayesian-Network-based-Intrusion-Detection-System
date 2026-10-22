/**
 * Finding the server without anyone typing its address.
 *
 * The launcher on the server's computer publishes the current tunnel address as a TXT
 * record on a name the owner controls (a free DuckDNS name). This page reads that record
 * through public DNS-over-HTTPS resolvers, so the address can change every run.
 *
 * Only https://<words>.trycloudflare.com is ever accepted from DNS: a spoofed or stale
 * record cannot send people to an arbitrary site to type their password into.
 */
const TUNNEL = /^https:\/\/[a-z0-9-]+\.trycloudflare\.com$/;

const NAME = /^(?=.{4,253}$)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$/;

export const validName = (value) => {
  const name = (value || "").trim().toLowerCase();

  return NAME.test(name) ? name : "";
};

/** The tunnel address inside a DNS-over-HTTPS JSON answer, or "". */
export function tunnelFromAnswer(body) {
  for (const answer of body?.Answer || []) {
    // TXT data arrives quoted, possibly split into several quoted pieces
    const text = String(answer.data || "")
      .replace(/"\s+"/g, "")
      .replace(/^"|"$/g, "")
      .trim();

    if (TUNNEL.test(text)) return text;
  }

  return "";
}

const RESOLVERS = [
  (name) => `https://dns.google/resolve?name=${encodeURIComponent(name)}&type=TXT`,
  (name) => `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=TXT`
];

/** Asks public resolvers for the current address; "" when none answers. */
export async function discover(name, fetcher = fetch) {
  const valid = validName(name);

  if (!valid) return "";

  for (const resolver of RESOLVERS) {
    try {
      const response = await fetcher(resolver(valid), {
        headers: { Accept: "application/dns-json" },
        cache: "no-store"
      });

      if (!response.ok) continue;

      const found = tunnelFromAnswer(await response.json());

      if (found) return found;
    } catch {
      /* try the next resolver */
    }
  }

  return "";
}
