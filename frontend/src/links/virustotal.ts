import { Link } from "@/types";

export class VirusTotal implements Link {
  public favicon: string;
  public baseURL: string;
  public name: string;

  public constructor() {
    this.name = "VirusTotal (Domain)";
    this.baseURL = "https://www.virustotal.com";
    this.favicon = "https://www.google.com/s2/favicons?domain=virustotal.com";
  }

  public href(hostname, _ip_address): string {
    return this.baseURL + `/gui/domain/${hostname}/detection`;
  }
}
