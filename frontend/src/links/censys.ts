import { Link } from "@/types";

export class Censys implements Link {
  public baseURL: string;
  public favicon: string;
  public name: string;

  public constructor() {
    this.baseURL = "https://censys.io";
    this.favicon = "https://www.google.com/s2/favicons?domain=censys.io";
    this.name = "Censys (IP)";
  }

  public href(_hostname, ipAddress): string {
    return this.baseURL + `/ipv4/${ipAddress}`;
  }
}
