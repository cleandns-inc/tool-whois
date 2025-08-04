export type WhoisTimestampFields = "created" | "updated" | "expires";

export type WhoisOptions = Partial<{
  fetch: typeof fetch;
  thinOnly: boolean;
  server: string;
}>;

export type WhoisResponse = {
  found: boolean;
  statusCode?: number;
  error?: string;
  server?: string;
  registrar: {
    id: string | number;
    name: string | null;
  };
  reseller: string | null;
  status: string[];
  statusDelta?: { status: string; thin: boolean; thick: boolean }[];
  nameservers: string[];
  ts: {
    created: Date | null;
    updated: Date | null;
    expires: Date | null;
  };
  identity?: {
    handle: string;
    ipRange: {
      start: string;
      endAddress: string;
    };
    cidr: string[];
    name: string;
    type: string;
    parent: string | null;
    ip: string;
  }
};
