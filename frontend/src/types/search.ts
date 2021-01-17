import { Match, Rule } from "@/types/rule";
import { Snapshot } from "@/types/snapshot";

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

/*
export interface SearchOptions {
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
*/

export interface SearchParams {
  [key: string]: string | number | undefined;
}
