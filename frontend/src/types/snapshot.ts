import { Dict } from "@/types/common";
import { Rule } from "@/types/rule";

export interface HTML {
  id: string;
  content: string;
  createdAt: string;
}

export interface Whois {
  id: string;
  content: string;
  createdAt: string;
}

export interface Certificate {
  id: string;
  content: string;
  createdAt: string;
}

export interface File {
  id: string;
  content: string;
  createdAt: string;
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
  headers: Dict;
  processing: boolean;
  createdAt: string;

  html: HTML;
  whois: Whois | null;
  certificate: Certificate | null;

  scripts: Script[];
  dnsRecords: DnsRecord[];
  classifications: Classification[];
  rules: Rule[];
}

export interface CreateSnapshotPayload {
  url: string;
  enableHar: boolean;
  acceptLanguage: string | undefined;
  host: string | undefined;
  ignoreHttpsErrors: boolean | undefined;
  referer: string | undefined;
  timeout: number;
  userAgent: string | undefined;
  deviceName: string | undefined;
}
