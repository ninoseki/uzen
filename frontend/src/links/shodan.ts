import { Link } from "@/types";

export class Shodan implements Link {
  public baseURL: string;
  public favicon: string;
  public name: string;

  public constructor() {
    this.baseURL = "https://shodan.io";
    this.favicon = "https://www.google.com/s2/favicons?domain=shodan.io";
    this.name = "Shodan (IP)";
  }

  public href(_hostname, ipAddress): string {
    return this.baseURL + `/host/${ipAddress}`;
  }
}
