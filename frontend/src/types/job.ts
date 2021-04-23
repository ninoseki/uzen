export interface Job {
  id: string;
  type: string;
}

export interface SnapshotJobResult {
  snapshotId: string;
}

export interface SnapshotJobStatus {
  id: string;
  isRunning: boolean;
  result: SnapshotJobResult | null;
}
