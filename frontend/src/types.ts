import {
  CountResponse,
  ErrorData,
  Header,
  ValidationError,
} from "@/types/common";
import { Device } from "@/types/devices";
import { DomainInformation } from "@/types/domain";
import { HAR } from "@/types/har";
import { IPAddressInformation } from "@/types/ip_address";
import { Link, LinkType } from "@/types/link";
import {
  CreateRulePayload,
  Match,
  MatchFilters,
  Rule,
  RuleFilters,
  TargetTypes,
  UpdateRulePayload,
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
  File,
  Headers,
  Script,
  Snapshot,
  SnapshotFilters,
  Stylesheet,
  WaitUntilType,
  Whois,
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
  Device,
  DnsRecord,
  DomainInformation,
  ErrorData,
  File,
  HAR,
  Header,
  Headers,
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
  Stylesheet,
  TargetTypes,
  UpdateRulePayload,
  ValidationError,
  WaitUntilType,
  Whois,
  YaraMatch,
  YaraMatchString,
  YaraResult,
  YaraScanPyalod,
};
