import { Link, LinkType } from "@/types";

export class Censys implements Link {
  public baseURL: string;
  public favicon: string;
  public name: string;
  public type: LinkType;

  public constructor() {
    this.baseURL = "https://search.censys.io";
    this.favicon = "https://www.google.com/s2/favicons?domain=censys.io";
    this.name = "Censys (IP)";
    this.type = "ip_address";
  }

  public href(hostname: string): string {
    return this.baseURL + `/hosts/${hostname}`;
  }
}
