import { API } from "@/api";
import {
  Certificate,
  DomainInformation,
  File,
  HAR,
  HTML,
  MatchSearchResults,
  SimilarityScanJobStatus,
  SnapshotJobStatus,
  YaraScanJobStatus,
  Indicators,
  IPAddressInformation,
  SearchParams,
  Rule,
  RuleSearchResults,
  Job,
  Device,
  CreateRulePayload,
  UpdateRulePayload,
  SnapshotSearchResults,
  SimilarityScanPayload,
  CreateSnapshotPayload,
  Snapshot,
  Whois,
  Status,
  YaraScanPayload,
} from "@/types";
import { useAsyncTask, Task } from "vue-concurrency";

export function generateGetCertificateTask(): Task<Certificate, [string]> {
  return useAsyncTask<Certificate, [string]>(async (_signal, id) => {
    return await API.getCertificate(id);
  });
}

export function generateGetDomainTask(): Task<DomainInformation, [string]> {
  return useAsyncTask<DomainInformation, [string]>(async (_signal, domain) => {
    return await API.getDomainInformation(domain);
  });
}

export function generateGetFileTask(): Task<File, [string]> {
  return useAsyncTask<File, [string]>(async (_signal, id) => {
    return await API.getFile(id);
  });
}

export function generateGetHARTask(): Task<HAR, [string]> {
  return useAsyncTask<HAR, [string]>(async (_signal, snapshotId) => {
    return await API.getHAR(snapshotId);
  });
}

export function generateGetHTMLTask(): Task<HTML, [string]> {
  return useAsyncTask<HTML, [string]>(async (_signal, id) => {
    return await API.getHTML(id);
  });
}

export function generateGetIndicatorsTask(): Task<Indicators, [string]> {
  return useAsyncTask<Indicators, [string]>(async (_signal, snapshotId) => {
    return await API.getIndicators(snapshotId);
  });
}

export function generateGetIPAddressTask(): Task<
  IPAddressInformation,
  [string]
> {
  return useAsyncTask<IPAddressInformation, [string]>(
    async (_signal, ipAddress) => {
      return await API.getIPAddressInformation(ipAddress);
    }
  );
}

export function generateGetSimilarityScanJobStatusTask(): Task<
  SimilarityScanJobStatus,
  [string]
> {
  return useAsyncTask<SimilarityScanJobStatus, [string]>(
    async (_signal, jobId) => {
      return await API.getSimilarityScanJobStatus(jobId);
    }
  );
}

export function generateGetSnapshotJobStatusTask(): Task<
  SnapshotJobStatus,
  [string]
> {
  return useAsyncTask<SnapshotJobStatus, [string]>(async (_signal, jobId) => {
    return await API.getSnapshotJobStatus(jobId);
  });
}

export function generateGetYaraScanJobStatusTask(): Task<
  YaraScanJobStatus,
  [string]
> {
  return useAsyncTask<YaraScanJobStatus, [string]>(async (_signal, jobId) => {
    return await API.getYaraScanJobStatus(jobId);
  });
}

export function generateSearchMatchesTask(): Task<
  MatchSearchResults,
  [SearchParams]
> {
  return useAsyncTask<MatchSearchResults, [SearchParams]>(
    async (_signal, params) => {
      return await API.searchMatches(params);
    }
  );
}

export function generateGetRuleTask(): Task<Rule, [string]> {
  return useAsyncTask<Rule, [string]>(async (_signal, id) => {
    return await API.getRule(id);
  });
}

export function generateCreateRuleTask(): Task<Rule, [CreateRulePayload]> {
  return useAsyncTask<Rule, [CreateRulePayload]>(async (_signal, payload) => {
    return await API.createRule(payload);
  });
}

export function generateEditRuleTask(): Task<
  Rule,
  [string, UpdateRulePayload]
> {
  return useAsyncTask<Rule, [string, UpdateRulePayload]>(
    async (_signal, id, payload) => {
      return await API.editRule(id, payload);
    }
  );
}

export function generateDeleteRuleTask(): Task<void, [string]> {
  return useAsyncTask<void, [string]>(async (_signal, id) => {
    return await API.deleteRule(id);
  });
}

export function generateSearchRulesTask(): Task<
  RuleSearchResults,
  [SearchParams]
> {
  return useAsyncTask<RuleSearchResults, [SearchParams]>(
    async (_signal, params) => {
      return await API.searchRules(params);
    }
  );
}

export function generateTakeSnapshotTask(): Task<Job, [CreateSnapshotPayload]> {
  return useAsyncTask<Job, [CreateSnapshotPayload]>(
    async (_signal, payload) => {
      return await API.takeSnapshot(payload);
    }
  );
}

export function generateSimilarityScanTask(): Task<
  Job,
  [SimilarityScanPayload, SearchParams]
> {
  return useAsyncTask<Job, [SimilarityScanPayload, SearchParams]>(
    async (_signal, payload, params) => {
      return await API.similarityScan(payload, params);
    }
  );
}

export function generateSearchSnapshotsTask(): Task<
  SnapshotSearchResults,
  [SearchParams]
> {
  return useAsyncTask<SnapshotSearchResults, [SearchParams]>(
    async (_signal, params) => {
      return await API.searchSnapshots(params);
    }
  );
}

export function generateDeleteSnapshotTask(): Task<void, [string]> {
  return useAsyncTask<void, [string]>(async (_signal, id) => {
    return await API.deleteSnapshot(id);
  });
}

export function generateGetDevicesTask(): Task<Device[], []> {
  return useAsyncTask<Device[], []>(async () => {
    return await API.getDevices();
  });
}

export function generateGetSnapshotTask(): Task<Snapshot, [string]> {
  return useAsyncTask<Snapshot, [string]>(async (_signal, id) => {
    return await API.getSnapshot(id);
  });
}

export function generateGetTextTask(): Task<string, [string]> {
  return useAsyncTask<string, [string]>(async (_signal, id) => {
    return await API.getText(id);
  });
}

export function generateGetWhoisTask(): Task<Whois, [string]> {
  return useAsyncTask<Whois, [string]>(async (_signal, id) => {
    return await API.getWhois(id);
  });
}

export function generateYaraScanTask(): Task<
  Job,
  [YaraScanPayload, SearchParams]
> {
  return useAsyncTask<Job, [YaraScanPayload, SearchParams]>(
    async (_signal, payload, params) => {
      return await API.yaraScan(payload, params);
    }
  );
}

export function generateImportFromUrlscanTask(): Task<Snapshot, [string]> {
  return useAsyncTask<Snapshot, [string]>(async (_signal, uuid) => {
    return await API.importFromUrlscan(uuid);
  });
}

export function generateGetStatusTask(): Task<Status, []> {
  return useAsyncTask<Status, []>(async () => {
    return await API.getStatus();
  });
}
