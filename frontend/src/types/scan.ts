export interface ScanOptions {
  asn: string | undefined;
  contentType: string | undefined;
  hostname: string | undefined;
  ipAddress: string | undefined;
  server: string | undefined;
  sha256: string | undefined;
  status: number | undefined;
  url: string | undefined;
  fromAt: string | undefined;
  toAt: string | undefined;
}

export interface Pager {
  size: number | null;
  offset: number | null;
}
