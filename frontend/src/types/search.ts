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

export interface SearchParams {
  [key: string]: string | number | undefined;
}
