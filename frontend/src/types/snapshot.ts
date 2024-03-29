import { Rule } from "@/types/rule";

export interface Headers {
  [header: string]: string | string[] | undefined;
}

export interface HTML {
  sha256: string;
  content: string | null;
  createdAt: string | null;
}

export interface Whois {
  id: string | null;
  content: string | null;
  createdAt: string | null;
  created: string | null;
  updated: string | null;
  expires: string | null;
  registrar: string | null;
  registrantName: string | null;
  registrantOrganization: string | null;
}

export interface Certificate {
  id: string;
  content: string | null;
  notAfter: string | null;
  notBefore: string | null;
  issuer: string;
  subject: string;
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
  sha256: string;
  createdAt: string | null;
}

export interface Stylesheet {
  id: string | null;
  url: string;
  sha256: string;
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
  hostname: string | undefined;
  ipAddress: string | undefined;
  hash: string | undefined;
  certificateFingerprint: string | undefined;
  status: number | undefined;
  url: string | undefined;
  tag: string | undefined;
  fromAt: Date | undefined;
  toAt: Date | undefined;
}

export interface Tag {
  name: string;
}

export interface Snapshot {
  id: string;
  url: string;
  submittedUrl: string;
  status: number;
  hostname: string;
  ipAddress: string;
  asn: string;
  countryCode: string;
  requestHeaders: Headers;
  responseHeaders: Headers;
  processing: boolean;
  createdAt: string;

  html: HTML;
  whois: Whois | null;
  certificate: Certificate | null;

  scripts: Script[];
  stylesheets: Stylesheet[];
  dnsRecords: DnsRecord[];
  classifications: Classification[];
  rules: Rule[];
  tags: Tag[];
}

export type WaitUntilType = "domcontentloaded" | "load" | "networkidle";

export interface CreateSnapshotPayload {
  url: string;
  enableHar: boolean;
  ignoreHttpsErrors: boolean | undefined;
  timeout: number;
  deviceName: string | undefined;
  headers: Headers;
  waitUntil: WaitUntilType;
}
