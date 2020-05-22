export interface Dict {
  [key: string]: string | number;
}

export interface Screenshot {
  id: string | undefined;
  data: string;
}

export interface Snapshot {
  id: string | undefined;
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
  createdAt: string | undefined;

  screenshot: Screenshot;

  scripts: Script[];
  dnsRecords: DnsRecord[];
  classifications: Classification[];
  rules: Rule[];
}

export interface ValidationError {
  loc: string[];
  msg: string;
  type: string;
}

export interface ErrorData {
  detail: string | ValidationError[];
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

export type LinkType = "ip_address" | "domain";

export interface Link {
  name: string;
  type: string;
  baseURL: string;
  favicon: string;
  href(hostname: string): string;
}

export interface Script {
  id: string | undefined;
  url: string;
  content: string;
  sha256: string;
  createdAt: string | undefined;
}

export interface DnsRecord {
  id: string | undefined;
  type: string;
  value: string;
  createdAt: string | undefined;
}

export interface Classification {
  id: string | undefined;
  name: string;
  malicious: boolean;
  note: string | undefined;
  createdAt: string | undefined;
}

export interface YaraMatchString {
  offset: number;
  stringIdentifier: string;
  stringData: string;
}

export interface YaraMatch {
  meta: Dict;
  namespace: string;
  rule: string;
  strings: YaraMatchString[];
  tags: string[];
}

export interface YaraResult {
  snapshotId: string;
  scriptId: string | undefined;
  target: string;
  matches: YaraMatch[];
}

export interface SnapshotWithYaraResult extends Snapshot {
  yaraResult: YaraResult | undefined;
}

export interface Oneshot {
  matched: boolean;
  matches: YaraMatch[];
  snapshot: Snapshot;
}

export type TargetTypes = "body" | "whois" | "certificate" | "script";

export interface Rule {
  id: string;
  name: string;
  target: TargetTypes;
  source: string;
  snapshots: Snapshot[];
  createdAt: string;
  updatedAt: string;
}

export interface RuleFilters {
  name: string | undefined;
  target: TargetTypes | undefined;
  source: string | undefined;
}

export interface Match {
  id: string;
  snapshot: Snapshot;
  rule: Rule;
  script: Script | undefined;
  matches: YaraMatch[];
  createdAt: string;
}

export interface MatchFilters {
  snapshotId: string | undefined;
  ruleId: string | undefined;
  fromAt: Date | undefined;
  toAt: Date | undefined;
}

// Search results
interface SearchResults {
  total: number;
}

export interface SnapshotSearchResults extends SearchResults {
  results: Snapshot[];
}

export interface MatchSearchResults extends SearchResults {
  results: Match[];
}

export interface RuleSearchResults extends SearchResults {
  results: Rule[];
}

export interface CountResponse {
  count: number;
}

// eslint-disable-next-line @typescript-eslint/interface-name-prefix
export interface IPAddressInformation {
  ipAddress: string;
  asn: string;
  country: string;
  description: string;
  whois: string | undefined;
  snapshots: Snapshot[];
}

export interface DomainInformation {
  hostname: string;
  whois: string | undefined;
  dnsRecords: DnsRecord[];
  snapshots: Snapshot[];
}
