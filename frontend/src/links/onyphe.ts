import { Link, LinkType } from "@/types";

export class Onyphe implements Link {
  public baseURL: string;
  public favicon: string;
  public name: string;
  public type: LinkType;

  public constructor() {
    this.baseURL = "https://www.onyphe.io";
    this.favicon = "https://www.google.com/s2/favicons?domain=onyphe.io";
    this.name = "Onyphe (IP)";
    this.type = "ip_address";
  }

  public href(hostname: string): string {
    return this.baseURL + `/summary/ip/${hostname}`;
  }
}
