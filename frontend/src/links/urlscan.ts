import { Link } from "@/types";

export class Urlscan implements Link {
  public favicon: string;
  public baseURL: string;
  public name: string;

  public constructor() {
    this.baseURL = "https://urlscan.io";
    this.favicon = "https://www.google.com/s2/favicons?domain=urlscan.io";
    this.name = "urlscan.io (Domain)";
  }

  public href(hostname, _ip_address): string {
    return this.baseURL + `/domain/${hostname}`;
  }
}
