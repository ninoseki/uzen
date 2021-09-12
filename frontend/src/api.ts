import { setup } from "axios-cache-adapter";

import { useGlobalState } from "@/store";
import {
  Certificate,
  CountResponse,
  CreateRulePayload,
  CreateSnapshotPayload,
  Device,
  DomainInformation,
  File,
  HAR,
  HTML,
  Indicators,
  IPAddressInformation,
  Job,
  MatchSearchResults,
  Rule,
  RuleSearchResults,
  SearchParams,
  SimilarityScanJobStatus,
  SimilarityScanPayload,
  Snapshot,
  SnapshotJobStatus,
  SnapshotSearchResults,
  Status,
  UpdateRulePayload,
  Whois,
  YaraScanJobStatus,
  YaraScanPayload,
} from "@/types";

const state = useGlobalState();

let client = setup({
  headers: {
    Accept: "application/json",
    "Api-key": state.value.apiKey,
  },
  cache: {
    maxAge: 0,
  },
});

export function updateClient(): void {
  client = setup({
    headers: {
      Accept: "application/json",
      "Api-key": state.value.apiKey,
    },
    cache: {
      maxAge: 0,
    },
  });
}

export const API = {
  async takeSnapshot(payload: CreateSnapshotPayload): Promise<Job> {
    const res = await client.post<Job>("/api/snapshots/", payload);
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

  async deleteSnapshot(snapshotId: string): Promise<void> {
    await client.delete(`/api/snapshots/${snapshotId}`);
  },

  async getIndicators(snapshotId: string): Promise<Indicators> {
    const res = await client.get<Indicators>(
      `/api/snapshots/${snapshotId}/indicators`
    );
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

  async deleteRule(ruleId: string): Promise<void> {
    await client.delete<void>(`/api/rules/${ruleId}`);
  },

  async searchRules(params: SearchParams): Promise<RuleSearchResults> {
    const res = await client.get<RuleSearchResults>(`/api/rules/search`, {
      params,
    });
    return res.data;
  },

  async yaraScan(payload: YaraScanPayload, params: SearchParams): Promise<Job> {
    const res = await client.post<Job>("/api/yara/scan", payload, { params });
    return res.data;
  },

  async similarityScan(
    payload: SimilarityScanPayload,
    params: SearchParams
  ): Promise<Job> {
    const res = await client.post<Job>("/api/similarity/scan", payload, {
      params,
    });
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

  async getWhois(sha256: string): Promise<Whois> {
    const res = await client.get<Whois>(`/api/whoises/${sha256}`, {
      cache: {
        maxAge: 60 * 60 * 1000,
      },
    });
    return res.data;
  },

  async getHTML(sha256: string): Promise<HTML> {
    const res = await client.get<HTML>(`/api/htmls/${sha256}`, {
      cache: {
        maxAge: 60 * 60 * 1000,
      },
    });
    return res.data;
  },

  async getText(sha256: string): Promise<string> {
    const res = await client.get<string>(`/api/htmls/${sha256}/text`, {
      cache: {
        maxAge: 60 * 60 * 1000,
      },
    });
    return res.data;
  },

  async getCertificate(sha256: string): Promise<Certificate> {
    const res = await client.get<Certificate>(`/api/certificates/${sha256}`, {
      cache: {
        maxAge: 60 * 60 * 1000,
      },
    });
    return res.data;
  },

  async getStatus(): Promise<Status> {
    const res = await client.get<Status>("/api/status/", {
      cache: {
        maxAge: 60 * 60 * 1000,
      },
    });
    return res.data;
  },

  async getSnapshotJobStatus(jobId: string): Promise<SnapshotJobStatus> {
    const res = await client.get<SnapshotJobStatus>(
      `/api/jobs/snapshots/${jobId}`
    );
    return res.data;
  },

  async getYaraScanJobStatus(jobId: string): Promise<YaraScanJobStatus> {
    const res = await client.get<YaraScanJobStatus>(`/api/jobs/yara/${jobId}`);
    return res.data;
  },

  async getSimilarityScanJobStatus(
    jobId: string
  ): Promise<SimilarityScanJobStatus> {
    const res = await client.get<SimilarityScanJobStatus>(
      `/api/jobs/similarity/${jobId}`
    );
    return res.data;
  },
};
