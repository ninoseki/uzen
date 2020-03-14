export interface Headers {
  [key: string]: string | number;
}

export interface Snapshot {
  id: number | undefined;
  url: string;
  submitted_url: string;
  status: number;
  hostname: string;
  ip_address: string;
  asn: string;
  server: string;
  content_type: string;
  content_lenth: number;
  body: string;
  sha256: string;
  headers: Headers;
  screenshot: string;
  whois: string | undefined;
  certificate: string | undefined;
  created_at: string | undefined;
}

export interface SnapshotCount {
  count: number;
}

export interface ErrorData {
  detail: string;
}

export interface SearchFilters {
  hostname: string | undefined;
  ip_address: string | undefined;
  asn: string | undefined;
  server: string | undefined;
  content_type: string | undefined;
  sha256: string | undefined;
  from_at: Date | undefined;
  to_at: Date | undefined;
}

export interface Link {
  name: string;
  baseURL: string;
  favicon: string;
  href(hostname: string | undefined, ip_address: string | undefined): string;
}

export interface Script {
  id: number | undefined;
  url: string;
  content: string;
  sha256: string;
  created_at: string | undefined;
}

export interface Oneshot {
  matched: boolean;
  snapshot: Snapshot;
  scripts: Script[];
}

export type TargetTypes = "body" | "whois" | "certificate" | "script";
