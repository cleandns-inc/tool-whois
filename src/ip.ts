import { WhoisResponse } from "../whois.js";

export function parseIpResponse(ip: string, rdap: any, response: WhoisResponse) {
  response.found = Boolean(rdap.handle);

  const registry = rdap.port43 ? rdap.port43.match(/\.(\w+)\./)[1].toUpperCase() : '';
  const realRdapServer = rdap.links?.find(({ rel }: { rel: string }) => rel === 'self')?.value?.replace(/\/ip\/.*/, '/ip/');

  response.server = realRdapServer || 'https://rdap.org/ip/';

  response.identity = {
    handle: rdap.handle,
    ipRange: {
      start: rdap.startAddress,
      endAddress: rdap.endAddress
    },
    cidr: (rdap.cidr0_cidrs || []).map((cidr: any) => cidr.v4prefix + '/' + cidr.length),
    name: rdap.name,
    type: rdap.type,
    parent: rdap.parentHandle,
    ip,
  };

  response.registrar = {
    id: 0,
    name: registry,
  };
}
