# CleanDNS Tools: WHOIS/RDAP lookup

WHOIS/RDAP lookups for domain names.

## Documentation

### `whois(target: string, options?: WhoisParameters): Promise<WhoisResponse>`

Performs an RDAP or port 43 WHOIS lookup for a given domain name, and attempts to normalize the response. When RDAP data is incomplete or inaccurate, the library automatically falls back to querying the registrar's WHOIS server directly for more accurate information.

### Parameters

- `target` (string): The domain name to look up.
- `options` (WhoisParameters): Optional parameters for WHOIS/RDAP resolution.
  - `fetch` (fetch): A drop-in replacement for Node's built-in `fetch`, useful for proxying RDAP lookups.
  - `thinOnly` (boolean): Whether to only fetch a registry-level ("thin") RDAP response, instead of attempting a registrar-level ("thick") response.
  
### Returns

- `Promise<WhoisResponse>`: A promise that resolves to a `WhoisResponse` object containing the RDAP or WHOIS information for the domain.

### WhoisResponse

An object containing the RDAP or WHOIS information for the domain.

- `found` (boolean): Whether the domain could be found via RDAP or port 43 lookup.
- `registrar` (object): The registrar information for the domain.
  - `id` (string): The registrar's ID (IANA or otherwise).
  - `name` (string): The registrar's name.
  - `email` (string): The registrar's abuse email contact, if available.
- `reseller` (string): The name of the domain's reseller, if available.
- `status` (string[]): The EPP statuses for the domain.
- `statusDelta` (object[]): Any discrepancies in EPP status between the registry response and the registrar response.
  - `status` (string): An EPP status.
  - `thin` (boolean): Whether this EPP status was only found in the registry (thin) response.
  - `thick` (boolean): Whether this EPP status was only found in the registrar (thick) response.
- `nameservers` (string[]): The nameservers for the domain.
- `ts` (object): The timestamps associated with the domain, if available.
  - `created` (Date): The registration or creation date for the domain.
  - `updated` (Date): The last update date for the domain.
  - `expires` (Date): The expiration date for the domain.

### Example

```typescript
import { whois } from '@cleandns/whois-rdap';

whois('example.com')
  .then((response) => {
    console.log(response);
  })
  .catch((error) => {
    console.error(error);
  });
```

## Installation

```
npm install @cleandns/whois
```

## Caveats / limitations

- This package is currently intended for **domain name** lookups only. IPv4/IPv6 address support is not guaranteed.

- Parsing of port 43 WHOIS responses is a work in progress.

- Registrar WHOIS fallback uses web-based proxies when direct port 43 access is not available.