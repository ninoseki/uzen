import { Link, LinkType } from "@/types";

export class Spyse implements Link {
  public favicon: string;
  public baseURL: string;
  public name: string;
  public type: LinkType;

  public constructor() {
    this.baseURL = "https://spyse.com";
    this.favicon = "https://www.google.com/s2/favicons?domain=spyse.com";
    this.name = "Spyse (IP)";
    this.type = "ip_address";
  }

  public href(hostname: string): string {
    return this.baseURL + `/target/ip/${hostname}`;
  }
}
