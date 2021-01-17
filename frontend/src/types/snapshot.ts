import { Dict } from "@/types/common";
import { Rule } from "@/types/rule";

export interface File {
  id: string;
  content: string;
}

export interface Script {
  id: string | null;
  url: string;
  file: File;
  createdAt: string | null;
}

export interface DnsRecord {
  id: string | null;
  type: string;
  value: string;
  createdAt: string | null;
}

export interface Classification {
  id: string | null;
  name: string;
  malicious: boolean;
  note: string | null;
  createdAt: string | null;
}

export interface SnapshotFilters {
  asn: string | undefined;
  contentType: string | undefined;
  hostname: string | undefined;
  ipAddress: string | undefined;
  server: string | undefined;
  sha256: string | undefined;
  status: number | undefined;
  url: string | undefined;
  fromAt: Date | undefined;
  toAt: Date | undefined;
}

export interface Snapshot {
  id: string;
  url: string;
  submittedUrl: string;
  status: number;
  hostname: string;
  ipAddress: string;
  asn: string;
  server: string;
  contentType: string;
  contentLength: number;
  body: string;
  sha256: string;
  headers: Dict;
  whois: string | undefined;
  certificate: string | undefined;
  processing: boolean;
  createdAt: string;

  scripts: Script[];
  dnsRecords: DnsRecord[];
  classifications: Classification[];
  rules: Rule[];
}

export interface CreateSnapshotPayload {
  url: string;
  acceptLanguage: string | undefined;
  host: string | undefined;
  ignoreHttpsErrors: boolean | undefined;
  referer: string | undefined;
  timeout: number;
  userAgent: string | undefined;
}
