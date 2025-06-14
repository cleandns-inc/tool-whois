import { WhoisOptions, WhoisResponse, WhoisTimestampFields } from "../whois.js";
import { parseIpResponse } from "./ip.js";
import { determinePort43Domain, port43 } from "./port43.js";
import { findInObject } from "./utils/findInObject.js";
import { fixArrays } from "./utils/fixArrays.js";
import { ianaIdToRegistrar } from "./utils/ianaIdToRegistrar.js";
import { tldToRdap } from "./utils/tldToRdap.js";
import { normalizeWhoisStatus } from "./whoisStatus.js";
import { resolve4 } from "dns/promises";

const eventMap = new Map<string, WhoisTimestampFields>([
  ["registration", "created"],
  ["last changed", "updated"],
  ["expiration", "expires"],
  ["expiration date", "expires"],
]);

export async function whois(
  origDomain: string,
  options: WhoisOptions = { fetch: fetch, thinOnly: false }
): Promise<WhoisResponse> {
  const _fetch = options.fetch || fetch;

  let domain = origDomain;
  let url: string | null = null;

  [domain, url] = await tldToRdap(origDomain);

  const response: WhoisResponse = {
    found: false,
    registrar: { id: 0, name: null },
    reseller: null,
    status: [],
    statusDelta: [],
    nameservers: [],
    ts: { created: null, updated: null, expires: null },
  };

  if (url !== null) {
    const host = new URL(url).host;
    /* check for A record via DNS lookup */
    const isLive = await resolve4(host).then((r) => Boolean(r?.length)).catch(() => false);
    if (!isLive) url = null;
  }

  if (url === null) {
    if (determinePort43Domain(domain)[2]) {
      return port43(domain, _fetch);
    }
    url = "https://rdap.org";
  }

  const type = domain.match(/[^\d.]/) ? "domain" : "ip";
  let thinResponse: any = null;
  const thinRdap = `${url}/${type}/${domain}`;

  // console.log(`fetching thin RDAP: ${thinRdap}`);

  thinResponse = await _fetch(thinRdap)
    .then((r) => r.json() as any)
    .catch(() => null);
  if (thinResponse && !thinResponse.errorCode) {
  } else if (!options.server) {
    return response;
  }

  if (thinResponse?.rdapConformance?.["0"]) {
    thinResponse = fixArrays(thinResponse);
  }

  const selfRdap = thinResponse?.links?.find((link: any) => link.rel === "self");

  const thickRdap = thinResponse.links
    ?.find(
      (link: any) =>
        link.href !== selfRdap?.href &&
        link.rel === "related" &&
        link.type === "application/rdap+json"
    )
    ?.href.replace("/domain/domain/", "/domain/") || `${options.server}/domain/${domain}`;

  let thickResponse: any = null;

  if (!options.thinOnly && thickRdap) {
    // console.log(`fetching thick RDAP: ${thickRdap}`);
    thickResponse = await _fetch(thickRdap)
      .then((r) => r.json() as any)
      .catch(() => null);
    if (thickResponse && !thickResponse.errorCode && !thickResponse.error) {
    } else {
      thickResponse = null;
      // console.warn(`thick RDAP failed for ${domain}`);
    }
  }

  if (thickResponse?.rdapConformance?.["0"]) {
    thickResponse = fixArrays(thickResponse);
  }

  const registrars: any[] = [];
  const resellers: any[] = [];

  async function extractRegistrarsAndResellers(response: any, url: string, isThick?: boolean) {
    for (const ent of [
      ...(response.entities || []),
      response.entity ? { events: response.events, ...response.entity } : null,
    ].filter(Boolean)) {
      if (ent.roles?.includes("registrar") || ent.role === "registrar") {
        const pubIds: any[] = [];
        if (ent.publicIds) {
          pubIds.push(
            ...(Array.isArray(ent.publicIds)
              ? ent.publicIds
              : [[ent.publicIds]])
          );
        }
        if (ent.publicIDs) {
          pubIds.push(
            ...(Array.isArray(ent.publicIDs)
              ? ent.publicIDs
              : [[ent.publicIDs]])
          );
        }
        const reg =
          pubIds.find((id: any) => id.type === "PANDI Registrar ID")?.Identifier
          || pubIds.find((id: any) => id.type === "PANDI Registrar ID")?.identifier
          || pubIds.find((id: any) => id.type === "IANA Registrar ID")?.Identifier
          || pubIds.find((id: any) => id.type === "IANA Registrar ID")?.identifier
          || pubIds.find((id: any) => id.type === "IANA RegistrarID")?.Identifier
          || pubIds.find((id: any) => id.type === "IANA RegistrarID")?.identifier
          || pubIds.find((id: any) => id.type === "IANA Registrar ID")
          ;

        if (reg) {
          // console.log(ent.vcardArray);
          const id = typeof reg === 'object' ? 0 : reg;
          const name =
            (parseInt(id) == id
              && (await ianaIdToRegistrar(parseInt(id)))?.name)
            || findInObject(
              ent.vcardArray,
              (el: any) =>
                Array.isArray(el) && (el[0] === "fn" || el[0] === "org"),
              (el: any[]) => el[3],
              reg
            );
          const email =
            [ent, ...(ent.entities || [])]
              .filter((e) => e?.vcardArray)
              .map((e) =>
                findInObject(
                  e.vcardArray,
                  (el: any) => Array.isArray(el) && el[0] === "email",
                  (el: any[]) => el[3],
                  ""
                )
              )
              .filter(Boolean)?.[0] || "";

          const events =
            ent.events || response.events || ent.enents || response.enents;
          registrars.push({ id, name, email, events });
        }
        // handles .ca
        else if (ent.vcardArray?.[1]?.[3]?.[3] === 'registrar') {
          const email =
            [ent, ...(ent.entities || [])]
              .filter((e) => e?.vcardArray)
              .map((e) =>
                findInObject(
                  e.vcardArray,
                  (el: any) => Array.isArray(el) && el[0] === "email",
                  (el: any[]) => el[3],
                  ""
                )
              )
              .filter(Boolean)?.[0] || "";

          registrars.push({ id: 0, name: ent.vcardArray[1][1][3], email, events: ent.events || response.events || ent.enents || response.enents });
        }
        // handles .si
        else if (ent.vcardArray?.[1].find((el: string[]) => el[0] === 'fn')) {
          const email =
            [ent, ...(ent.entities || [])]
              .filter((e) => e?.vcardArray)
              .map((e) =>
                findInObject(
                  e.vcardArray,
                  (el: any) => Array.isArray(el) && el[0] === "email",
                  (el: any[]) => el[3],
                  ""
                )
              )
              .filter(Boolean)?.[0] || "";

          if (ent.handle && ent.handle.toString().match(/^\d+$/)) {
            const id = ent.handle;
            const name =
              (parseInt(id) == id
                && (await ianaIdToRegistrar(parseInt(id)))?.name)
              || findInObject(
                ent.vcardArray,
                (el: any) =>
                  Array.isArray(el) && (el[0] === "fn" || el[0] === "org"),
                (el: any[]) => el[3],
                id
              );
            registrars.push({ id, name, email, events: ent.events || response.events || ent.enents || response.enents });
          }
          else {
            registrars.push({ id: ent.handle || 0, name: ent.vcardArray[1].find((el: string[]) => el[0] === 'fn')[3], email, events: ent.events || response.events || ent.enents || response.enents });
          }
        }
        // handles .ar
        else if (ent.handle) {
          registrars.push({ id: 0, name: ent.handle, email: '', events: ent.events || response.events || ent.enents || response.enents });
        }

      }

      if (
        domain.endsWith(".is") &&
        (ent.roles?.includes("technical") || ent.role === "technical")
      ) {
        const id = ent.handle;
        const name =
          (parseInt(id) == id
            && (await ianaIdToRegistrar(parseInt(id)))?.name)
          || findInObject(
            ent.vcardArray,
            (el: any) =>
              Array.isArray(el) && (el[0] === "fn" || el[0] === "org"),
            (el: any[]) => el[3],
            id
          );
        const email =
          [ent, ...(ent.entities || [])]
            .filter((e) => e?.vcardArray)
            .map((e) =>
              findInObject(
                e.vcardArray,
                (el: any) => Array.isArray(el) && el[0] === "email",
                (el: any[]) => el[3],
                ""
              )
            )
            .filter(Boolean)?.[0] || "";

        const events =
          ent.events || response.events || ent.enents || response.enents;
        registrars.push({ id, name, email, events });
      }

      if (
        (ent.roles?.includes("reseller") || ent.role === "reseller") &&
        ent.vcardArray
      ) {
        // vcard objects can be unexpectedly and arbitrarily nested
        const name = findInObject(
          ent.vcardArray,
          (el: any) => Array.isArray(el) && (el[0] === "fn" || el[0] === "org"),
          (el: any[]) => el[3],
          ""
        );
        resellers.push({ name });
      }
    }
  }

  if (thickResponse && !thickResponse.errorCode) {
    await extractRegistrarsAndResellers(thickResponse, thickRdap, true);
  }
  if (thinResponse && !thinResponse.errorCode) {
    await extractRegistrarsAndResellers(thinResponse, thinRdap, false);
  }

  response.found = true;

  // registrar
  const { events, ...registrar } = registrars.sort((a: any, b: any) => {
    const aDate = (
      (a.events || []).find((ev: any) => ev.eventAction === "registration")
        ?.eventDate || 0
    )
      .toString()
      .replace(/\+0000Z$/, "Z");
    const bDate = (
      (b.events || []).find((ev: any) => ev.eventAction === "registration")
        ?.eventDate || 0
    )
      .toString()
      .replace(/\+0000Z$/, "Z");
    return new Date(bDate).valueOf() - new Date(aDate).valueOf();
  })[0] || { id: 0, name: "" };
  response.registrar = registrar;

  // reseller
  const reseller = resellers[0]?.name || "";
  response.reseller = reseller;

  // status
  const statusThin = findStatus(thinResponse?.status || [], domain);
  const statusThick = findStatus(thickResponse?.status || [], domain);
  response.status = [...new Set([...statusThin, ...statusThick])];

  response.statusDelta = [];
  for (const status of response.status) {
    const thin = statusThin.includes(status) || statusThin.includes(status.replace(/^client/, "server")) || statusThin.includes(status.replace(/^server/, "client"));
    const thick = statusThick.includes(status) || statusThick.includes(status.replace(/^client/, "server")) || statusThick.includes(status.replace(/^server/, "client"));
    if (thin !== thick) {
      response.statusDelta.push({ status, thin, thick });
    }
  }

  // nameservers
  response.nameservers = findNameservers(
    thickResponse?.nameservers || thinResponse?.nameservers || []
  );

  // ts
  response.ts = findTimestamps([
    ...(thickResponse?.events || []),
    ...(thinResponse?.events || []),
  ]);

  if (type === 'ip') parseIpResponse(domain, thinResponse, response);

  return response;
}

function findStatus(statuses: string | string[], domain: string): string[] {
  // console.warn({ domain, statuses });

  return (Array.isArray(statuses)
    ? statuses
    : statuses && typeof statuses === "object"
      ? Object.keys(statuses)
      : typeof statuses === "string"
        ? statuses.trim().split(/\s*,\s*/)
        : []
  ).map((status) => normalizeWhoisStatus(status));
}

function findNameservers(values: any[]): string[] {
  let nameservers: any[] = [];
  if (Array.isArray(values)) {
    nameservers = values;
  } else if (typeof values === "object") {
    nameservers = Object.values(values);
  }

  return nameservers
    .map((ns) => ns.ldhName || ns.ldnName || ns.ipAddresses?.v4)
    .flat()
    .filter((ns) => ns)
    .map((ns) => (ns.stringValue || ns).toLocaleLowerCase())
    .sort();
}

function findTimestamps(values: any[]) {
  const ts: Record<WhoisTimestampFields, Date | null> = {
    created: null,
    updated: null,
    expires: null,
  };

  let events: any = [];

  if (Array.isArray(values)) {
    events = values;
  } else if (typeof values === "object") {
    events = Object.values(values);
  }

  for (const [event, field] of eventMap) {
    const date = events.find(
      (ev: any) => ev?.eventAction?.toLocaleLowerCase() === event
    );
    if (date?.eventDate) {
      ts[field] = new Date(date.eventDate.toString().replace(/\+0000Z$/, "Z"));
    }
  }

  return ts;
}
