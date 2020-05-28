import { Link, LinkType } from "@/types";

export class BinaryEdge implements Link {
  public baseURL: string;
  public favicon: string;
  public name: string;
  public type: LinkType;

  public constructor() {
    this.baseURL = "https://app.binaryedge.io";
    this.favicon = "https://www.google.com/s2/favicons?domain=binaryedge.io";
    this.name = "BinaryEdge (IP)";
    this.type = "ip_address";
  }

  public href(hostname: string): string {
    return this.baseURL + `/services/query/${hostname}`;
  }
}
