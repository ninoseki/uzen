export type LinkType = "ip_address" | "domain";

export interface Link {
  name: string;
  type: string;
  baseURL: string;
  favicon: string;
  // eslint-disable-next-line no-unused-vars
  href(hostname: string): string;
}
