// Polyfills for Node.js 18 compatibility
import "./polyfills.js";

import { WhoisOptions, WhoisResponse, WhoisTimestampFields } from "../whois.js";
import { parseIpResponse } from "./ip.js";
import { determinePort43Domain, port43 } from "./port43.js";
import { findInObject } from "./utils/findInObject.js";
import { fixArrays } from "./utils/fixArrays.js";
import { ianaIdToRegistrar } from "./utils/ianaIdToRegistrar.js";
import { tldToRdap } from "./utils/tldToRdap.js";
import { resolve4 } from "dns/promises";
import { toArray } from "./utils/toArray.js";
import { validateDomain } from "./utils/validateDomain.js";
import { findStatus } from "./utils/findStatus.js";
import { findNameservers } from "./utils/findNameservers.js";
import { findTimestamps } from "./utils/findTimestamps.js";
import createDebug from "debug";
import { escapeRegex } from "./utils/escapeRegex.js";

// Debug logger - enable with DEBUG=whois:* environment variable
const debug = createDebug("whois:rdap");

export const eventMap = new Map<string, WhoisTimestampFields>([
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

  // Validate and sanitize input
  let domain: string;
  try {
    domain = validateDomain(origDomain);
  } catch (e: any) {
    return {
      found: false,
      statusCode: 400,
      error: e.message,
      registrar: { id: 0, name: null },
      reseller: null,
      status: [],
      statusDelta: [],
      nameservers: [],
      ts: { created: null, updated: null, expires: null },
    };
  }

  let url: string | null = null;

  [domain, url] = await tldToRdap(domain);

  const response: WhoisResponse = {
    found: false,
    statusCode: 0,
    error: '',
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

  thinResponse = await _fetch(thinRdap)
    .then((r) => {
      response.statusCode = r.status;
      if (r.status >= 200 && r.status < 400) {
        return r.json() as any;
      }
      response.error = r.statusText;
      return null;
    })
    .catch((error: Error) => {
      debug("thin RDAP lookup failure for %s: %s", domain, error.message);
      return null;
    });

  if (thinResponse && !thinResponse.errorCode) {
  } else if (!options.server) {
    return response;
  }

  if (thinResponse?.rdapConformance?.["0"]) {
    thinResponse = fixArrays(thinResponse);
  }

  const selfRdap = thinResponse?.links?.find((link: any) => link.rel === "self");

  // Find the thick RDAP URL from the thin response's links
  const thickRdapFromLinks = thinResponse?.links
    ?.find(
      (link: any) =>
        link.href !== selfRdap?.href &&
        link.rel === "related" &&
        link.type === "application/rdap+json"
    )
    ?.href.replace("/domain/domain/", "/domain/");

  // Only use options.server as fallback if it's actually defined
  // This prevents constructing invalid URLs like "undefined/domain/example.com"
  const thickRdap = thickRdapFromLinks || (options.server ? `${options.server}/domain/${domain}` : null);

  let thickResponse: any = null;

  if (!options.thinOnly && thickRdap) {
    debug("fetching thick RDAP: %s", thickRdap);
    thickResponse = await _fetch(thickRdap)
      .then((r) => r.json() as any)
      .catch(() => null);
    if (thickResponse && !thickResponse.errorCode && !thickResponse.error) {
    } else {
      thickResponse = null;
      debug("thick RDAP failed for %s", domain);
    }
  }

  if (thickResponse?.rdapConformance?.["0"]) {
    thickResponse = fixArrays(thickResponse);
  }

  const registrars: any[] = [];
  const resellers: any[] = [];

  async function extractRegistrarsAndResellers(response: any, url: string, isThick?: boolean) {
    // Use toArray to safely handle entities that might not be iterable
    const entities = toArray(response.entities);
    const entityList = [
      ...entities,
      response.entity ? { events: response.events, ...response.entity } : null,
    ].filter(Boolean);

    for (const ent of entityList) {
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
          || pubIds.find((id: any) => id.type === "Registry Identifier")?.identifier
          || pubIds.find((id: any) => id.type === "IANA Registrar ID")
          ;

        if (reg) {
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
          // Safely handle ent.entities
          const entEntities = toArray(ent.entities);
          const email =
            [ent, ...entEntities]
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

          const abuseEmail =
            [ent, ...entEntities]
              .filter((e) => e?.vcardArray)
              .map((e) =>
                findInObject(
                  e.vcardArray,
                  (el: any) => Array.isArray(el) && e.roles?.includes("abuse") && el[0] === "email",
                  (el: any[]) => el[3],
                  ""
                )
              )
              .filter(Boolean)?.[0] || "";

          const events =
            ent.events || response.events || ent.enents || response.enents;
          registrars.push({ id, name, email, abuseEmail, events });
        }
        // handles .ca - with safe optional chaining
        else if (ent.vcardArray?.[1]?.[3]?.[3] === 'registrar') {
          const entEntities = toArray(ent.entities);
          const email =
            [ent, ...entEntities]
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

          const abuseEmail =
            [ent, ...entEntities]
              .filter((e) => e?.vcardArray)
              .map((e) =>
                findInObject(
                  e.vcardArray,
                  (el: any) => Array.isArray(el) && e.roles?.includes("abuse") && el[0] === "email",
                  (el: any[]) => el[3],
                  ""
                )
              )
              .filter(Boolean)?.[0] || "";

          const vcardName = ent.vcardArray?.[1]?.[1]?.[3] || '';
          registrars.push({ id: 0, name: vcardName, email, abuseEmail, events: ent.events || response.events || ent.enents || response.enents });
        }
        // handles .si - with safe array access
        else if (ent.vcardArray && Array.isArray(ent.vcardArray[1]) && ent.vcardArray[1].find((el: string[]) => el[0] === 'fn')) {
          const entEntities = toArray(ent.entities);
          const email =
            [ent, ...entEntities]
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

          const abuseEmail =
            [ent, ...entEntities]
              .filter((e) => e?.vcardArray)
              .map((e) =>
                findInObject(
                  e.vcardArray,
                  (el: any) => Array.isArray(el) && e.roles?.includes("abuse") && el[0] === "email",
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
            registrars.push({ id, name, email, abuseEmail, events: ent.events || response.events || ent.enents || response.enents });
          }
          else {
            const fnEntry = ent.vcardArray[1].find((el: string[]) => el[0] === 'fn');
            const name = fnEntry ? fnEntry[3] : ent.handle || '';
            registrars.push({ id: ent.handle || 0, name, email, abuseEmail, events: ent.events || response.events || ent.enents || response.enents });
          }
        }
        // handles .ar
        else if (ent.handle) {
          registrars.push({ id: 0, name: ent.handle, email: '', abuseEmail: '', events: ent.events || response.events || ent.enents || response.enents });
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
        const entEntities = toArray(ent.entities);
        const email =
          [ent, ...entEntities]
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

        const abuseEmail =
          [ent, ...entEntities]
            .filter((e) => e?.vcardArray)
            .map((e) =>
              findInObject(
                e.vcardArray,
                (el: any) => Array.isArray(el) && e.roles?.includes("abuse") && el[0] === "email",
                (el: any[]) => el[3],
                ""
              )
            )
            .filter(Boolean)?.[0] || "";

        const events =
          ent.events || response.events || ent.enents || response.enents;
        registrars.push({ id, name, email, abuseEmail, events });
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
