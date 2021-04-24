import { CreateSnapshotPayload } from "@/types/snapshot";

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
  definition: SnapshotJobDefinition | null;
}
