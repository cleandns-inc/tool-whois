/**
 * Mapping of known registrar names to their WHOIS servers
 * Based on common registrars and their WHOIS servers
 */
export const registrarWhoisServers: Record<string, string> = {
  // Major registrars
  "namesilo": "whois.namesilo.com",
  "namesilo, llc": "whois.namesilo.com",
  "namesilo llc": "whois.namesilo.com",
  "godaddy": "whois.godaddy.com",
  "godaddy.com": "whois.godaddy.com",
  "godaddy.com, llc": "whois.godaddy.com",
  "godaddy, llc": "whois.godaddy.com",
  "namecheap": "whois.namecheap.com",
  "namecheap, inc": "whois.namecheap.com",
  "namecheap inc": "whois.namecheap.com",
  "google": "whois.nic.google",
  "google inc": "whois.nic.google",
  "google llc": "whois.nic.google",
  "google domains": "whois.nic.google",
  "cloudflare": "whois.cloudflare.com",
  "cloudflare, inc": "whois.cloudflare.com",
  "cloudflare inc": "whois.cloudflare.com",
  "dynadot": "whois.dynadot.com",
  "dynadot, llc": "whois.dynadot.com",
  "dynadot llc": "whois.dynadot.com",
  "gandi": "whois.gandi.net",
  "gandi sas": "whois.gandi.net",
  "hover": "whois.hover.com",
  "tucows": "whois.tucows.com",
  "tucows, inc": "whois.tucows.com",
  "tucows inc": "whois.tucows.com",
  "enom": "whois.enom.com",
  "enom, inc": "whois.enom.com",
  "enom inc": "whois.enom.com",
  "network solutions": "whois.networksolutions.com",
  "network solutions, llc": "whois.networksolutions.com",
  "network solutions llc": "whois.networksolutions.com",
  "porkbun": "whois.porkbun.com",
  "porkbun llc": "whois.porkbun.com",
  "ionos": "whois.ionos.com",
  "1&1 ionos": "whois.ionos.com",
  "1and1": "whois.1and1.com",
  "1&1": "whois.1and1.com",
  "bluehost": "whois.bluehost.com",
  "bluehost inc": "whois.bluehost.com",
  "domain.com": "whois.domain.com",
  "domain.com, llc": "whois.domain.com",
  "domain.com llc": "whois.domain.com",
  "squarespace": "whois.squarespace.com",
  "squarespace, inc": "whois.squarespace.com",
  "squarespace inc": "whois.squarespace.com",
  "wix": "whois.wix.com",
  "wix.com": "whois.wix.com",
  "wix.com ltd": "whois.wix.com",
  "epik": "whois.epik.com",
  "epik, inc": "whois.epik.com",
  "epik inc": "whois.epik.com",
  "ovh": "whois.ovh.com",
  "ovh sas": "whois.ovh.com",
  "dreamhost": "whois.dreamhost.com",
  "dreamhost, llc": "whois.dreamhost.com",
  "dreamhost llc": "whois.dreamhost.com",
  "fastdomain": "whois.fastdomain.com",
  "fastdomain, inc": "whois.fastdomain.com",
  "fastdomain inc": "whois.fastdomain.com",
  "register.com": "whois.register.com",
  "register.com, inc": "whois.register.com",
  "register.com inc": "whois.register.com",
  "123-reg": "whois.123-reg.co.uk",
  "123-reg limited": "whois.123-reg.co.uk",
  "moniker": "whois.moniker.com",
  "moniker online services": "whois.moniker.com",
  "moniker online services llc": "whois.moniker.com",
  "fabulous": "whois.fabulous.com",
  "fabulous.com": "whois.fabulous.com",
  "fabulous.com pty ltd": "whois.fabulous.com",
  "key-systems": "whois.key-systems.net",
  "key-systems gmbh": "whois.key-systems.net",
  "opensrs": "whois.opensrs.net",
  "opensrs (via tucows)": "whois.opensrs.net",
  "reseller club": "whois.resellerclub.com",
  "resellerclub": "whois.resellerclub.com",
  "bigrock": "whois.bigrock.com",
  "bigrock solutions": "whois.bigrock.com",
  "web.com": "whois.web.com",
  "web.com group": "whois.web.com",
  "web.com, inc": "whois.web.com",
  "web.com inc": "whois.web.com",
  "crazy domains": "whois.crazydomains.com",
  "crazydomains": "whois.crazydomains.com",
  "name.com": "whois.name.com",
  "name.com, inc": "whois.name.com",
  "name.com inc": "whois.name.com",
  "dotster": "whois.dotster.com",
  "dotster, inc": "whois.dotster.com",
  "dotster inc": "whois.dotster.com",
};

/**
 * Common misspellings and variations of WHOIS server URLs
 */
export const misspelledWhoisServers: Record<string, string> = {
  "whois.google.com": "whois.nic.google",
  "www.gandi.net/whois": "whois.gandi.net",
  "who.godaddy.com/": "whois.godaddy.com",
  "whois.godaddy.com/": "whois.godaddy.com",
  "www.nic.ru/whois/en/": "whois.nic.ru",
  "www.whois.corporatedomains.com": "whois.corporatedomains.com",
  "www.safenames.net/DomainNames/WhoisSearch.aspx": "whois.safenames.net",
  "WWW.GNAME.COM/WHOIS": "whois.gname.com",
  "www.gname.com/whois": "whois.gname.com",
  "whois.networksolutions.com/": "whois.networksolutions.com",
  "www.networksolutions.com/whois": "whois.networksolutions.com",
  "whois.tucows.com/": "whois.tucows.com",
  "www.tucows.com/whois": "whois.tucows.com",
  "whois.enom.com/": "whois.enom.com",
  "www.enom.com/whois": "whois.enom.com",
  "whois.namecheap.com/": "whois.namecheap.com",
  "www.namecheap.com/whois": "whois.namecheap.com",
  "whois.namesilo.com/": "whois.namesilo.com",
  "www.namesilo.com/whois": "whois.namesilo.com",
};

/**
 * Get the WHOIS server for a given registrar name
 */
export function getRegistrarWhoisServer(registrarName: string): string | null {
  if (!registrarName) return null;
  
  const normalized = registrarName.toLowerCase().trim();
  return registrarWhoisServers[normalized] || null;
}

/**
 * Fix common WHOIS server URL misspellings
 */
export function fixWhoisServerUrl(server: string): string {
  if (!server) return server;
  
  const normalized = server.toLowerCase().trim();
  return misspelledWhoisServers[normalized] || server;
}

/**
 * Extract WHOIS server from various response field names
 */
export function extractWhoisServer(data: any): string | null {
  if (!data) return null;
  
  const possibleFields = [
    "Registrar WHOIS Server",
    "Registry WHOIS Server", 
    "ReferralServer",
    "Registrar Whois",
    "Whois Server",
    "WHOIS Server",
    "whois",
    "registrar_whois_server",
    "Registrar URL"
  ];
  
  for (const field of possibleFields) {
    const value = data[field];
    if (value && typeof value === 'string') {
      let server = value.trim();
      
      // Handle URLs - extract hostname
      if (server.includes('://')) {
        try {
          const url = new URL(server);
          server = url.hostname;
        } catch {
          // If URL parsing fails, try to extract manually
          const match = server.match(/\/\/([^\/]+)/);
          if (match) server = match[1];
        }
      }
      
      // Special cases for known registrars
      if (field === "Registrar URL") {
        if (server.includes('domains.google')) {
          return "whois.nic.google";
        }
        if (server.includes('godaddy')) {
          return "whois.godaddy.com";
        }
        if (server.includes('namesilo')) {
          return "whois.namesilo.com";
        }
        if (server.includes('namecheap')) {
          return "whois.namecheap.com";
        }
        if (server.includes('gandi')) {
          return "whois.gandi.net";
        }
        // If it's just a registrar URL but not a WHOIS server, skip it
        continue;
      }
      
      // Fix common misspellings
      server = fixWhoisServerUrl(server);
      
      // Only return if it looks like a valid WHOIS server
      if (server && (server.includes('whois.') || server.includes('.whois'))) {
        return server;
      }
    }
  }
  
  return null;
}
