export type WhoisTimestampFields = "created" | "updated" | "expires";

export type WhoisOptions = Partial<{
  fetch: typeof fetch;
  thinOnly: boolean;
}>;

export type WhoisResponse = {
  found: boolean;
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
};
