export type WhoisTimestampFields = "created" | "updated" | "expires";

export type WhoisOptions = Partial<{
  fetch: typeof fetch;
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
  nameservers: string[];
  ts: {
    created: Date | null;
    updated: Date | null;
    expires: Date | null;
  }
};
