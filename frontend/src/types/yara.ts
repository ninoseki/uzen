import { Dict } from "@/types/common";
import { Pager, ScanOptions } from "@/types/scan";

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

export interface YaraScanPayloadWithSearchOptions
  extends YaraScanPayload,
    Pager {
  filters: ScanOptions;
}
