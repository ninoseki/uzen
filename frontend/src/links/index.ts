import { Censys } from "./censys";
import { Crtsh } from "./crtsh";
import { SecurityTrails } from "./securitytrails";
import { Spyse } from "./spyse";
import { Shodan } from "./shodan";
import { Urlscan } from "./urlscan";
import { VirusTotal } from "./virustotal";

export const Links = [
  new Censys(),
  new Crtsh(),
  new SecurityTrails(),
  new Shodan(),
  new Spyse(),
  new Urlscan(),
  new VirusTotal()
];
