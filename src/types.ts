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

export interface ErrorData {
  detail: string;
}
