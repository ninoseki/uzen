import { Pager, ScanOptions } from "@/types/scan";

export interface SimilarityScanPayload {
  html: string;
  threshold: number;
  excludeHostname: string | undefined;
  excludeIPAddress: string | undefined;
}

export interface SimilarityScanPayloadWithSearchOptions
  extends SimilarityScanPayload,
    Pager {
  filters: ScanOptions;
}
