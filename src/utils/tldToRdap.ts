import { ParseResultType, parseDomain } from "parse-domain";

type TldToRdap = [string[], string[]];
let tldCache = new Map<string, string | null>([]);
const tldCachePresets: [string, string | null][] = [
  ["it.com", null],
  ["br.com", "https://rdap.centralnic.com/br.com"],
  ["cn.com", "https://rdap.centralnic.com/cn.com"],
  ["de.com", "https://rdap.centralnic.com/de.com"],
  ["eu.com", "https://rdap.centralnic.com/eu.com"],
  ["gb.com", "https://rdap.centralnic.com/gb.com"],
  ["gb.net", "https://rdap.centralnic.com/gb.net"],
  ["gr.com", "https://rdap.centralnic.com/gr.com"],
  ["hu.com", "https://rdap.centralnic.com/hu.com"],
  ["in.net", "https://rdap.centralnic.com/in.net"],
  ["jpn.com", "https://rdap.centralnic.com/jpn.com"],
  ["no.com", "https://rdap.centralnic.com/no.com"],
  ["qc.com", "https://rdap.centralnic.com/qc.com"],
  ["ru.com", "https://rdap.centralnic.com/ru.com"],
  ["sa.com", "https://rdap.centralnic.com/sa.com"],
  ["se.com", "https://rdap.centralnic.com/se.com"],
  ["se.net", "https://rdap.centralnic.com/se.net"],
  ["uk.com", "https://rdap.centralnic.com/uk.com"],
  ["uk.net", "https://rdap.centralnic.com/uk.net"],
  ["us.com", "https://rdap.centralnic.com/us.com"],
  ["uy.com", "https://rdap.centralnic.com/uy.com"],
  ["web.com", "https://rdap.centralnic.com/web.com"],
  ["za.com", "https://rdap.centralnic.com/za.com"],
  ["ch", "https://rdap.nic.ch"],
];

export async function tldToRdap(
  domain: string
): Promise<[string, string | null]> {
  if (tldCache.size === 0) {
    const tmpCache = new Map<string, string | null>([]);
    for (const [tld, url] of tldCachePresets) {
      tmpCache.set(tld, url);
    }

    // console.warn(`fetching tld-to-rdap`);
    const response: { services: TldToRdap[] } = await fetch(
      `https://data.iana.org/rdap/dns.json`
    ).then((r) => r.json() as any);

    for (const [tlds, urls] of response.services) {
      for (const tld of tlds) {
        tmpCache.set(tld, urls[0].replace(/\/$/, ""));
      }
    }
    tldCache = tmpCache;
  }

  const parsed = parseDomain(domain);

  if (parsed.type === ParseResultType.Listed) {
    for (let i = 0; i < parsed.topLevelDomains.length; i++) {
      let tld = parsed.topLevelDomains.slice(i).join('.');
      if (tldCache.has(tld)) {
        return [
          [ parsed.domain, parsed.topLevelDomains.join('.') ].join('.'),
          tldCache.get(tld)!
        ]
      }
    }

    // Check ICANN
    for (let i = 0; i < parsed.icann.topLevelDomains.length; i++) {
      let tld = parsed.icann.topLevelDomains.slice(i).join('.');
      if (tldCache.has(tld)) {
        return [
          [ parsed.domain, parsed.icann.topLevelDomains.join('.') ].join('.'),
          tldCache.get(tld)!
        ]
      }
    }
  }
  else if (parsed.type === ParseResultType.Ip) {
    return [domain, "https://rdap.org"];
  }

  return [domain, null];
}
