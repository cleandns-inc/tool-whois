import { ParseResultType, parseDomain } from "parse-domain";

type TldToRdap = [string[], string[]];
const tldCache = new Map<string, string>([]);
const tldCachePresets = [
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
];

export async function tldToRdap(domain: string): Promise<[ string, string | null ]> {
  if (tldCache.size === 0) {
    for (const [tld, url] of tldCachePresets) {
      tldCache.set(tld, url);
    }

    // console.warn(`fetching tld-to-rdap`);
    const response: { services: TldToRdap[]; } = await fetch(
      `https://data.iana.org/rdap/dns.json`
    ).then((r) => r.json() as any);

    for (const [tlds, urls] of response.services) {
      for (const tld of tlds) {
        tldCache.set(tld, urls[0].replace(/\/$/, ''));
      }
    }
  }

  const parsed = parseDomain(domain);

  if (parsed.type === ParseResultType.Listed) {
    let tld = parsed.topLevelDomains.join(".");
    if (tldCache.has(tld)) {
      return [ parsed.domain + '.' + tld, tldCache.get(tld)! ];
    }
    tld = parsed.icann.topLevelDomains.join(".");
    if (tldCache.has(tld)) {
      return [ parsed.icann.domain + '.' + tld, tldCache.get(tld)! ];
    }

    // const tlds = [
    //   parsed.topLevelDomains.join("."),
    //   // parsed.icann.topLevelDomains.join("."),
    // ];

    // for (const tld of tlds) {
    //   if (tldCache.has(tld)) {
    //     return tldCache.get(tld);
    //   }
    // }
  }

  return [ domain, null ];
}