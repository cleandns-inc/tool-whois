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
  const isWwww = opts?.url;
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
    if (isWwww) {
      port43response = (await fetch(opts.url.replace('%%domain%%', domain)).then(r => r.text())).toString().replace(/^[ \t]+/gm, "");
      response.server = opts.url.match('//(.*?)/')?.[1];
    }
    else {
      response.server = server;
      port43response = await fetch(`https://www.whois.com/whois/${domain}`).then(r => r.text()).then((r) => {
        return r.match(/<pre class="df-raw" id="registryData">(.*?)<\/pre>/s)?.[1] || "";
      });

      if (port43response === '') {
        const promiseSocket = new PromiseSocket(new Socket());
        promiseSocket.setTimeout(5 * 1000);
        await promiseSocket.connect(port, server);
        await promiseSocket.write(query);
        port43response = (await promiseSocket.readAll())!
          .toString()
          .replace(/\r/g, "")
          .replace(/^[ \t]+/gm, "");
        await promiseSocket.end();
      }
    }
  } catch (error: any) {
    console.warn(port, server, query);
    response.found = false;
  }

  if (!response.found) {
    return response;
  }

  // console.log(port43response);

  if (
    port43response.match(
      /^%*\s+(NOT FOUND|No match|NO OBJECT FOUND|No entries found|No Data Found|Domain is available for registration|No information available|Status: free)\b/im
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
      /^registrar(?:-name)?\.*:[ \t]*(\S.+)\s*\(\s*http.*/m
    )) &&
    (response.registrar.name = m[1].trim());
  !response.registrar.name &&
    (m = port43response.match(
      /^(?:(?:Sponsoring )?Registrar(?: Name)?|registrar\Wname|registrar|Registration service provider)\.*:[ \t]*(\S.+)/im
    )) &&
    (response.registrar.name = m[1].trim());
  !response.registrar.name &&
    (m = port43response.match(
      /^REGISTRAR:[ \t]*\n(\S.+)/m
    )) &&
    (response.registrar.name = m[1].trim());
  !response.registrar.name &&
    (m = port43response.match(
      /^\[Registrar\]\s*(?:[^\n:]+:.*\n)*Name:[ \t]*(\S.+)/m
    )) &&
    (response.registrar.name = m[1].trim());

  !response.registrar.id &&
    (m = port43response.match(/^Registrar IANA ID:[ \t]*(\d+)/im)) &&
    (response.registrar.id = parseInt(m[1] || "0"));

  !response.reseller &&
    (m = port43response.match(
      /^(?:Reseller(?: Name)?|reseller_name|reseller):[ \t]*(\S.+)/im
    )) &&
    (response.reseller = m[1].trim());

  !response.ts.updated &&
    (m = port43response.match(
      /^(?:Last Modified|Updated Date|Last updated on|domain_datelastmodified|last-update|modified|last modified)\.*:[ \t]*(\S.+)/im
    )) &&
    (response.ts.updated = new Date(reformatDate(m[1])) || null);
  !response.ts.updated &&
    (m = port43response.match(
      /^\[Last Updated?\][ \t]+(\S.+)/im
    )) &&
    (response.ts.updated = new Date(reformatDate(m[1])) || null);

  !response.ts.created &&
    (m = port43response.match(
      /^(?:Creation Date|domain_dateregistered|Registered|created|Created date|Domain created)\.*:[ \t]*(\S.+)/im
    )) &&
    (response.ts.created = new Date(reformatDate(m[1])) || null);
  !response.ts.created &&
    (m = port43response.match(
      /^(?:Record created on |\[(?:Created on|Registered Date)\][ \t]+)(\S.+)/im
    )) &&
    (response.ts.created = new Date(reformatDate(m[1])) || null);

  !response.ts.expires &&
    (m = port43response.match(
      /^(?:(?:Registry )?Expiry Date|Expiration date|expires?|Exp date|paid-till|free-date|renewal date)\.*:[ \t]*(\S.+)/im
    )) &&
    (response.ts.expires = new Date(reformatDate(m[1])) || null);
  !response.ts.expires &&
    (m = port43response.match(
      /^(?:Record expires on |\[Expires on\][ \t]+)(\S.+)/im
    )) &&
    (response.ts.expires = new Date(reformatDate(m[1])) || null);

  !response.status?.length && (m = port43response.match(/^(?:Status|Domain [Ss]tatus|status)\.*:.*/gm)) &&
    m.forEach((s) => {
      let m;
      (m = s.match(
        /^(?:Status|Domain [Ss]tatus|status)\.*:[ \t]*(?:<a[^>]*>)?(\S+)/m
      )) && m[1].split(/\s*,\s*/).map((status) => response.status.push(normalizeWhoisStatus(status)));
    });
  !response.status?.length && (m = port43response.match(/^Domain status : ((?:\S+ -\s*)+)/m)) &&
    m[1].match(/\w+/g)?.map((status) => response.status.push(normalizeWhoisStatus(status)));

  !response.nameservers?.length && (m = port43response.match(
    /^(?:Hostname|DNS|Name Server|ns_name_\d+|name?server|nserver|(?:primary|secondary) server)\.*:.*/gmi
  )) &&
    m.forEach((s) => {
      let m;
      (m = s.match(
        /^(?:Hostname|DNS|Name Server|ns_name_\d+|name?server|nserver|(?:primary|secondary) server)\.*:[ \t]*(\S+)/mi
      )) && response.nameservers.push(m[1].toLowerCase());
    });
  !response.nameservers?.length && (m = port43response.match(
    /^(?:\w. )?\[Name Server\][ \t]*\S+/gmi
  )) &&
    m.forEach((s) => {
      let m;
      (m = s.match(
        /\[Name Server\][ \t]*(\S+)/mi
      )) && response.nameservers.push(m[1].toLowerCase());
    });
  !response.nameservers?.length && (m = port43response.match(
    /^DNS servers\s*((?:Name\.+:.+\n)+)/mi
  )) &&
    m[1].match(/[^.\s]+(?:\.[^.\s]+)+/g)?.forEach((s) => {
      response.nameservers.push(s.toLowerCase());
    });
  !response.nameservers?.length && (m = port43response.match(
    /^Domain servers in listed order:\s*((?:\S+[ \t]*\n)+)/mi
  )) &&
    m[1].trim().split(/\s+/).forEach((s) => {
      response.nameservers.push(s.toLowerCase());
    });
  !response.nameservers?.length && (m = port43response.match(
    /^nameservers:[ \t]*(\S+(?:[ \t]*\n\S+)+)/m
  )) &&
    m[1].match(/[^.\s]+(?:\.[^.\s]+)+/g)?.forEach((s) => {
      response.nameservers.push(s.toLowerCase());
    });

  if (response.ts.created && !response.ts.created.valueOf()) response.ts.created = null;
  if (response.ts.updated && !response.ts.updated.valueOf()) response.ts.updated = null;
  if (response.ts.expires && !response.ts.expires.valueOf()) response.ts.expires = null;

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


function reformatDate(date: string) {
  if (date.match(/^\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d \(UTC[+-]\d+\)$/)) {
    return date;
  }
  if (date.match(/CLST$/)) {
    return date.replace(/CLST$/, "-0400");
  }
  if (date.match(/CLT$/)) {
    return date.replace(/CLT$/, "-0300");
  }

  const dmy = date.match(/^(\d\d)\W(\d\d)\W(\d\d\d\d)(\b.*)$/);
  if (dmy) {
    return `${dmy[3]}-${dmy[2]}-${dmy[1]}${dmy[4]}`;
  }

  const ymd = date.match(/^(\d\d\d\d)(\d\d)(\d\d)\b/);
  if (ymd) {
    return `${ymd[1]}-${ymd[2]}-${ymd[3]}`;
  }

  return date;
}