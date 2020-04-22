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
  headers: Dict;
  whois: string | undefined;
  certificate: string | undefined;
  processing: boolean;
  created_at: string | undefined;

  screenshot: Screenshot;

  scripts: Script[];
  dns_records: DnsRecord[];
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
  content_type: string | undefined;
  hostname: string | undefined;
  ip_address: string | undefined;
  server: string | undefined;
  sha256: string | undefined;
  status: number | undefined;
  url: string | undefined;
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
  id: string | undefined;
  url: string;
  content: string;
  sha256: string;
  created_at: string | undefined;
}

export interface DnsRecord {
  id: string | undefined;
  type: string;
  value: string;
  created_at: string | undefined;
}

export interface Classification {
  id: string | undefined;
  name: string;
  malicious: boolean;
  note: string | undefined;
  created_at: string | undefined;
}

export interface YaraMatchString {
  offset: number;
  string_identifier: string;
  string_data: string;
}

export interface YaraMatch {
  meta: Dict;
  namespace: string;
  rule: string;
  strings: YaraMatchString[];
  tags: string[];
}

export interface YaraResult {
  snapshot_id: string;
  script_id: string | undefined;
  target: string;
  matches: YaraMatch[];
}

export interface SnapshotWithYaraResult extends Snapshot {
  yara_result: YaraResult | undefined;
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
  created_at: string;
  updated_at: string;
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
  created_at: string;
}

export interface MatchFilters {
  snapshot_id: string | undefined;
  rule_id: string | undefined;
  from_at: Date | undefined;
  to_at: Date | undefined;
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
