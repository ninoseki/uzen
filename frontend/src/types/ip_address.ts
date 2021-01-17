import { Snapshot } from "@/types/snapshot";

export interface IPAddressInformation {
  ipAddress: string;
  asn: string;
  country: string;
  description: string;
  whois: string | null;
  snapshots: Snapshot[];
}
