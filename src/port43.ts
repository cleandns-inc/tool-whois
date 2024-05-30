import { ParseResultType, parseDomain } from "parse-domain";
import { PromiseSocket } from "promise-socket";
import { Socket } from "net";
import { port43servers, port43parsers } from "./port43servers.js";
import { ianaToRegistrarCache } from "./utils/ianaIdToRegistrar.js";
import { WhoisResponse } from "../whois.js";
import { normalizeWhoisStatus } from "./whoisStatus.js";

export function determinePort43Domain(actor: string) {
  const parsed = parseDomain(actor);

  if (parsed.type === ParseResultType.Listed) {
    let tld = parsed.topLevelDomains.join(".");
    if (port43servers[tld] || port43servers[tld.replace(/^[^.]+\./, "*.")]) {
      const domain = parsed.domain + "." + tld;
      return [domain, tld, port43servers[tld] || port43servers[tld.replace(/^[^.]+\./, "*.")]];
    }

    tld = parsed.icann.topLevelDomains.join(".");
    if (port43servers[tld] || port43servers[tld.replace(/^[^.]+\./, "*.")]) {
      const domain = parsed.icann.domain + "." + tld;
      return [domain, tld, port43servers[tld] || port43servers[tld.replace(/^[^.]+\./, "*.")]];
    }
  }

  return [actor, "", null];
}

export async function port43(actor: string): Promise<WhoisResponse> {
  const [domain, tld, whoisServer] = determinePort43Domain(actor);
  const opts = whoisServer;
  const server = opts?.host || opts || null;
  const query = opts?.query
    ? opts.query.replace("$addr", domain)
    : `${domain}\r\n`;
  const port = opts?.port || 43;

  // console.log(`looking up ${domain} on ${server}`);

  const response: WhoisResponse = {
    found: true,
    registrar: { id: 0, name: null },
    reseller: null,
    status: [],
    nameservers: [],
    ts: { created: null, updated: null, expires: null },
  };

  if (!server) {
    return response;
  }

  let port43response = "";

  try {
    const promiseSocket = new PromiseSocket(new Socket());
    promiseSocket.setTimeout(5 * 1000);
    await promiseSocket.connect(port, server);
    await promiseSocket.write(query);
    port43response = (await promiseSocket.readAll())!
      .toString()
      .replace(/^[ \t]+/gm, "");
    await promiseSocket.end();
  } catch (error) {
    response.found = false;
  }

  if (!response.found) {
    return response;
  }

  if (
    port43response.match(
      /^%*\s+(NOT FOUND|No match|NO OBJECT FOUND|No entries found|No Data Found|No information available|Status: free)\b/im
    )
  ) {
    response.found = false;
    return response;
  }

  let m;

  const parser = port43parsers[tld] || Object.entries(port43parsers).find(([t]) => tld.endsWith('.' + t))?.[1];

  if (parser) {
      await parser(port43response, response);
  }

  !response.registrar.name &&
    (m = port43response.match(
      /^(?:Registrar(?: Name)?|registrar_name|registrar):[ \t]*(\S.+)/m
    )) &&
    (response.registrar.name = m[1]);
  !response.reseller &&
    (m = port43response.match(
      /^(?:Reseller(?: Name)?|reseller_name|reseller):[ \t]*(\S.+)/m
    )) &&
    (response.reseller = m[1]);
  !response.registrar.id &&
    (m = port43response.match(/^Registrar IANA ID:[ \t]*(\d+)/m)) &&
    (response.registrar.id = parseInt(m[1] || "0"));
  !response.ts.updated &&
    (m = port43response.match(
      /^(?:Last Modified|Updated Date|domain_datelastmodified|last-update):[ \t]*(\S.+)/m
    )) &&
    (response.ts.updated = new Date(m[1]) || null);
  !response.ts.created &&
    (m = port43response.match(
      /^(?:Creation Date|domain_dateregistered|created):[ \t]*(\S.+)/m
    )) &&
    (response.ts.created = new Date(m[1]) || null);
  !response.ts.expires &&
    (m = port43response.match(
      /^(?:(?:Registry )?Expiry Date):[ \t]*(\S.+)/m
    )) &&
    (response.ts.expires = new Date(m[1]) || null);
  !response.status?.length && (m = port43response.match(/^(?:Status|Domain Status|status):.*/gm)) &&
    m.forEach((s) => {
      let m;
      (m = s.match(
        /^(?:Status|Domain Status|status):[ \t]*(?:<a[^>]*>)?(\S+)/m
      )) && response.status.push(normalizeWhoisStatus(m[1]));
    });
  !response.nameservers?.length && (m = port43response.match(
    /^(?:Name Server|ns_name_\d+|namserver|nserver):.*/gm
  )) &&
    m.forEach((s) => {
      let m;
      (m = s.match(
        /^(?:Name Server|ns_name_\d+|namserver|nserver):[ \t]*(.*)/m
      )) && response.nameservers.push(m[1].toLowerCase());
    });

  if (response.registrar.id === 0 && response.registrar.name !== "") {
    for (const [id, { name }] of ianaToRegistrarCache.entries()) {
      if (name === response.registrar.name) {
        response.registrar.id = id;
        break;
      }
    }
  }

  if (response.registrar.id === 0 && response.registrar.name !== "") {
    for (const [id, { name }] of ianaToRegistrarCache.entries()) {
      if (name.match(new RegExp(`\\b${response.registrar.name}\\b`, "i"))) {
        response.registrar.id = id;
        break;
      }
    }
  }

  if (response.registrar.id === 0 && response.registrar.name) {
    for (const [id, { name }] of ianaToRegistrarCache.entries()) {
      if (
        name.match(
          new RegExp(`\\b${response.registrar.name.replace(/,.*/, "")}\\b`, "i")
        )
      ) {
        response.registrar.id = id;
        break;
      }
    }
  }

  return response;
}
