import { setup } from "axios-cache-adapter";

import { useGlobalState } from "@/store";
import {
  CountResponse,
  CreateRulePayload,
  CreateSnapshotPayload,
  Device,
  DomainInformation,
  File,
  IPAddressInformation,
  MatchSearchResults,
  Rule,
  RuleSearchResults,
  SearchParams,
  Snapshot,
  SnapshotSearchResults,
  SnapshotWithYaraResult,
} from "@/types";
import { HAR, UpdateRulePayload, YaraScanPyalod } from "@/types";

const state = useGlobalState();

let client = setup({
  headers: {
    Accept: "application/json",
    "Api-key": state.value.apiKey,
  },
});

export function updateClient(): void {
  client = setup({
    headers: {
      Accept: "application/json",
      "Api-key": state.value.apiKey,
    },
  });
}

export const API = {
  async takeSnapshot(payload: CreateSnapshotPayload): Promise<Snapshot> {
    const res = await client.post<Snapshot>("/api/snapshots/", payload);
    return res.data;
  },

  async searchSnapshots(params: SearchParams): Promise<SnapshotSearchResults> {
    const res = await client.get<SnapshotSearchResults>(
      "/api/snapshots/search",
      {
        params,
      }
    );
    return res.data;
  },

  async getSnapshot(snapshotId: string): Promise<Snapshot> {
    const res = await client.get<Snapshot>(`/api/snapshots/${snapshotId}`);
    return res.data;
  },

  async getTotalSnapshotCount(): Promise<CountResponse> {
    const res = await client.get<CountResponse>("/api/snapshots/count");
    return res.data;
  },

  async searchMatches(params: SearchParams): Promise<MatchSearchResults> {
    const res = await client.get<MatchSearchResults>("/api/matches/search", {
      params,
    });
    return res.data;
  },

  async getRule(ruleId: string): Promise<Rule> {
    const res = await client.get<Rule>(`/api/rules/${ruleId}`);
    return res.data;
  },

  async createRule(payload: CreateRulePayload): Promise<Rule> {
    const res = await client.post<Rule>("/api/rules/", payload);
    return res.data;
  },

  async editRule(ruleId: string, payload: UpdateRulePayload): Promise<Rule> {
    const res = await client.put<Rule>(`/api/rules/${ruleId}`, payload);
    return res.data;
  },

  async searchRules(params: SearchParams): Promise<RuleSearchResults> {
    const res = await client.get<RuleSearchResults>(`/api/rules/search`, {
      params,
    });
    return res.data;
  },

  async yaraScan(
    payload: YaraScanPyalod,
    params: SearchParams
  ): Promise<SnapshotWithYaraResult[]> {
    const res = await client.post<SnapshotWithYaraResult[]>(
      "/api/yara/scan",
      payload,
      { params }
    );
    return res.data;
  },

  async getDomainInformation(hostname: string): Promise<DomainInformation> {
    const res = await client.get<DomainInformation>(`/api/domain/${hostname}`);
    return res.data;
  },

  async getIPAddressInformation(
    ipAddress: string
  ): Promise<IPAddressInformation> {
    const res = await client.get<IPAddressInformation>(
      `/api/ip_address/${ipAddress}`
    );
    return res.data;
  },

  async getHAR(snapshot_id: string): Promise<HAR> {
    const res = await client.get<HAR>(`/api/hars/${snapshot_id}`);
    return res.data;
  },

  async importFromUrlscan(uuid: string): Promise<Snapshot> {
    const res = await client.post<Snapshot>(`/api/import/${uuid}`);
    return res.data;
  },

  async getDevices(): Promise<Device[]> {
    const res = await client.get<Device[]>("/api/devices/", {
      cache: {
        maxAge: 60 * 60 * 1000,
      },
    });
    return res.data;
  },

  async getFile(sha256: string): Promise<File> {
    const res = await client.get<File>(`/api/files/${sha256}`, {
      cache: {
        maxAge: 60 * 60 * 1000,
      },
    });
    return res.data;
  },
};
