import { Script, Snapshot } from "@/types/snapshot";
import { YaraMatch } from "@/types/yara";

export type TargetTypes = "html" | "whois" | "certificate" | "script";

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
  script: Script | null;
  matches: YaraMatch[];
  createdAt: string;
}

export interface MatchFilters {
  snapshotId: string | undefined;
  ruleId: string | undefined;
  fromAt: Date | undefined;
  toAt: Date | undefined;
}

export interface CreateRulePayload {
  name: string;
  target: string;
  source: string;
}

export interface UpdateRulePayload {
  name: string | undefined;
  target: string | undefined;
  source: string | undefined;
}
