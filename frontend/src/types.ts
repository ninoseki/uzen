export interface Headers {
  [key: string]: string | number;
}

export interface Snapshot {
  id: number;
  url: string;
  status: number;
  hostname: string;
  ip_address: string;
  server: string;
  content_type: string;
  content_lenth: number;
  body: string;
  headers: Headers;
  screenshot: string;
  created_at: string;
}

export interface SnapshotData {
  snapshot: Snapshot;
}

export interface SnapshotsData {
  snapshots: Snapshot[];
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
