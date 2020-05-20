import { Link, LinkType } from "@/types";

export class SecurityTrails implements Link {
  public baseURL: string;
  public favicon: string;
  public name: string;
  public type: LinkType;

  public constructor() {
    this.baseURL = "https://securitytrails.com";
    this.favicon =
      "https://www.google.com/s2/favicons?domain=securitytrails.com";
    this.name = "SecurityTrails (Domain)";
    this.type = "domain";
  }

  public href(hostname: string): string {
    return this.baseURL + `/domain/${hostname}/dns`;
  }
}
