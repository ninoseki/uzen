import { Link } from "@/types";

export class Crtsh implements Link {
  public baseURL: string;
  public favicon: string;
  public name: string;

  public constructor() {
    this.baseURL = "https://crt.sh";
    this.favicon = "https://www.google.com/s2/favicons?domain=crt.sh";
    this.name = "crt.sh (Domain)";
  }

  public href(hostname, _ipAddress): string {
    return this.baseURL + `/?q=${hostname}`;
  }
}
