import { Link, LinkType } from "@/types";

export class UrlscanForDomain implements Link {
  public favicon: string;
  public baseURL: string;
  public name: string;
  public type: LinkType;

  public constructor() {
    this.baseURL = "https://urlscan.io";
    this.favicon = "https://www.google.com/s2/favicons?domain=urlscan.io";
    this.name = "urlscan.io (Domain)";
    this.type = "domain";
  }

  public href(hostname: string): string {
    return this.baseURL + `/domain/${hostname}`;
  }
}

export class UrlscanForIP implements Link {
  public favicon: string;
  public baseURL: string;
  public name: string;
  public type: LinkType;

  public constructor() {
    this.baseURL = "https://urlscan.io";
    this.favicon = "https://www.google.com/s2/favicons?domain=urlscan.io";
    this.name = "urlscan.io (IP)";
    this.type = "ip_address";
  }

  public href(hostname: string): string {
    return this.baseURL + `/ip/${hostname}`;
  }
}
