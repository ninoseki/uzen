import { Link } from "@/types";

export class SecurityTrails implements Link {
  public baseURL: string;
  public favicon: string;
  public name: string;

  public constructor() {
    this.baseURL = "https://securitytrails.com";
    this.favicon =
      "https://www.google.com/s2/favicons?domain=securitytrails.com";
    this.name = "SecurityTrails (Domain)";
  }

  public href(hostname, _ipAddress): string {
    return this.baseURL + `/domain/${hostname}/dns`;
  }
}
