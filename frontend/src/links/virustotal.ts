import { Link, LinkType } from "@/types";

export class VirusTotal implements Link {
  public favicon: string;
  public baseURL: string;
  public name: string;
  public type: LinkType;

  public constructor() {
    this.name = "VirusTotal (Domain)";
    this.baseURL = "https://www.virustotal.com";
    this.favicon = "https://www.google.com/s2/favicons?domain=virustotal.com";
    this.type = "domain";
  }

  public href(hostname: string): string {
    return this.baseURL + `/gui/domain/${hostname}/detection`;
  }
}
