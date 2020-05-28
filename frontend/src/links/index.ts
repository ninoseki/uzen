import { Link } from "@/types";

import { BinaryEdge } from "./binaryedge";
import { Censys } from "./censys";
import { Crtsh } from "./crtsh";
import { Onyphe } from "./onyphe";
import { SecurityTrailsForDomain, SecurityTrailsForIP } from "./securitytrails";
import { Shodan } from "./shodan";
import { Spyse } from "./spyse";
import { UrlscanForDomain, UrlscanForIP } from "./urlscan";
import { VirusTotalForDomain, VirusTotalForIP } from "./virustotal";

export const Links: Link[] = [
  new BinaryEdge(),
  new Censys(),
  new Crtsh(),
  new Onyphe(),
  new SecurityTrailsForDomain(),
  new SecurityTrailsForIP(),
  new Shodan(),
  new Spyse(),
  new UrlscanForDomain(),
  new UrlscanForIP(),
  new VirusTotalForDomain(),
  new VirusTotalForIP(),
];
