import { DnsRecord, Snapshot } from "@/types/snapshot";

export interface DomainInformation {
  hostname: string;
  whois: string | null;
  dnsRecords: DnsRecord[];
  snapshots: Snapshot[];
}
