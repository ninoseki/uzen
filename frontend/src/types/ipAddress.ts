import { Snapshot } from "@/types/snapshot";
import { Whois } from "@/types/snapshot";

export interface IPAddressInformation {
  ipAddress: string;
  asn: string;
  countryCode: string;
  description: string;
  whois: Whois | null;
  snapshots: Snapshot[];
}
