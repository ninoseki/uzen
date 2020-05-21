import { Link } from "@/types";

import { Censys } from "./censys";
import { Crtsh } from "./crtsh";
import { SecurityTrails } from "./securitytrails";
import { Shodan } from "./shodan";
import { Spyse } from "./spyse";
import { Urlscan } from "./urlscan";
import { VirusTotal } from "./virustotal";

export const Links: Link[] = [
  new Censys(),
  new Crtsh(),
  new SecurityTrails(),
  new Shodan(),
  new Spyse(),
  new Urlscan(),
  new VirusTotal(),
];
