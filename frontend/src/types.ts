import { CountResponse, ErrorData, ValidationError } from "@/types/common";
import { DomainInformation } from "@/types/domain";
import { IPAddressInformation } from "@/types/ip_address";
import { Link, LinkType } from "@/types/link";
import {
  CreateRulePayload,
  Match,
  MatchFilters,
  Rule,
  RuleFilters,
  TargetTypes,
} from "@/types/rule";
import {
  MatchSearchResults,
  RuleSearchResults,
  SearchParams,
  SnapshotSearchResults,
} from "@/types/search";
import {
  Classification,
  CreateSnapshotPayload,
  DnsRecord,
  Script,
  Snapshot,
  SnapshotFilters,
} from "@/types/snapshot";
import {
  YaraMatch,
  YaraMatchString,
  YaraResult,
  YaraScanPyalod,
} from "@/types/yara";

export interface SnapshotWithYaraResult extends Snapshot {
  yaraResult: YaraResult | null;
}

export {
  Classification,
  CountResponse,
  CreateRulePayload,
  CreateSnapshotPayload,
  DnsRecord,
  DomainInformation,
  ErrorData,
  IPAddressInformation,
  Link,
  LinkType,
  Match,
  MatchFilters,
  MatchSearchResults,
  Rule,
  RuleFilters,
  RuleSearchResults,
  Script,
  SearchParams,
  Snapshot,
  SnapshotFilters,
  SnapshotSearchResults,
  TargetTypes,
  ValidationError,
  YaraMatch,
  YaraMatchString,
  YaraResult,
  YaraScanPyalod,
};
