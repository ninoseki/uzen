import { Link } from "@/types";

export class Spyse implements Link {
  public favicon: string;
  public baseURL: string;
  public name: string;

  public constructor() {
    this.baseURL = "https://spyse.com";
    this.favicon = "https://www.google.com/s2/favicons?domain=spyse.com";
    this.name = "Spyse (IP)";
  }

  public href(_hostname, ip_address): string {
    return this.baseURL + `/target/ip/${ip_address}`;
  }
}
