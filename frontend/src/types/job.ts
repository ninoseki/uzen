import { SnapshotWithYaraResult } from "@/types";
import { SimilarityScanPayloadWithSearchOptions } from "@/types/similarity";
import { CreateSnapshotPayload, Snapshot } from "@/types/snapshot";
import { YaraScanPayloadWithSearchOptions } from "@/types/yara";

export interface Job {
  id: string;
  type: string;
}

export interface SnapshotJobResult {
  snapshotId: string;
}

export interface SnapshotJobDefinition {
  enqueueTime: string;
  payload: CreateSnapshotPayload;
}

export interface SnapshotJobStatus {
  id: string;
  isRunning: boolean;
  result: SnapshotJobResult | null;
  definition: SnapshotJobDefinition;
}

export interface YaraScanJobResult {
  scanResults: SnapshotWithYaraResult[];
}

export interface YaraScanJobDefinition {
  enqueueTime: string;
  payload: YaraScanPayloadWithSearchOptions;
}

export interface YaraScanJobStatus {
  id: string;
  isRunning: boolean;
  result: YaraScanJobResult | null;
  definition: YaraScanJobDefinition;
}

export interface SimilarityScanJobDefinition {
  enqueueTime: string;
  payload: SimilarityScanPayloadWithSearchOptions;
}

export interface SimilarityScanJobResult {
  scanResults: Snapshot[];
}

export interface SimilarityScanJobStatus {
  id: string;
  isRunning: boolean;
  result: SimilarityScanJobResult;
  definition: SimilarityScanJobDefinition;
}
