import {
  CountResponse,
  ErrorData,
  Header,
  ValidationError,
} from "@/types/common";
import { Device } from "@/types/devices";
import { DomainInformation } from "@/types/domain";
import { HAR } from "@/types/har";
import { Indicators } from "@/types/indicators";
import { IPAddressInformation } from "@/types/ipAddress";
import {
  Job,
  SimilarityScanJobStatus,
  SnapshotJobStatus,
  SnapshotWithSimilarity,
  SnapshotWithYaraResult,
  YaraScanJobStatus,
} from "@/types/job";
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
import { SimilarityScanPayload } from "@/types/similarity";
import {
  Certificate,
  Classification,
  CreateSnapshotPayload,
  DnsRecord,
  File,
  Headers,
  HTML,
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
  YaraScanPayload,
} from "@/types/yara";

export interface Status {
  ipAddress: string;
  countryCode: string;
}

export {
  Certificate,
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
  HTML,
  Indicators,
  IPAddressInformation,
  Job,
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
  SimilarityScanJobStatus,
  SimilarityScanPayload,
  Snapshot,
  SnapshotFilters,
  SnapshotJobStatus,
  SnapshotSearchResults,
  SnapshotWithSimilarity,
  SnapshotWithYaraResult,
  Stylesheet,
  TargetTypes,
  UpdateRulePayload,
  ValidationError,
  WaitUntilType,
  Whois,
  YaraMatch,
  YaraMatchString,
  YaraResult,
  YaraScanJobStatus,
  YaraScanPayload,
};
