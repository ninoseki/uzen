import { Dict } from "@/types/common";

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
  scriptId: string | null;
  target: string;
  matches: YaraMatch[];
}

export interface YaraScanPayload {
  target: string;
  source: string;
}

export interface YaraScanOptions {
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
