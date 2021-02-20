import { DnsRecord, Snapshot } from "@/types/snapshot";
import { Whois } from "@/types/snapshot";

export interface DomainInformation {
  hostname: string;
  whois: Whois | null;
  dnsRecords: DnsRecord[];
  snapshots: Snapshot[];
}
