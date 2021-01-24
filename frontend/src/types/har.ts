export interface Creator {
  name: string;
  version: string;
}

export interface Browser {
  name: string;
  version: string;
}

export interface PageTimings {
  onContentLoad: number;
  onLoad: number;
}

export interface Page {
  startedDateTime: Date;
  id: string;
  title: string;
  pageTimings: PageTimings;
}

export interface Cooky {
  name: string;
  value: string;
}

export interface Header {
  name: string;
  value: string;
}

export interface QueryString {
  name: string;
  value: string;
}

export interface Request {
  method: string;
  url: string;
  httpVersion: string;
  cookies: Cooky[];
  headers: Header[];
  queryString: QueryString[];
  headersSize: number;
  bodySize: number;
}

export interface Cooky2 {
  name: string;
  value: string;
  secure: boolean;
  sameSite: string;
  httpOnly?: boolean;
}

export interface Header2 {
  name: string;
  value: string;
}

export interface Content {
  size: number;
  mimeType: string;
  text: string;
  encoding: string;
}

export interface Response {
  status: number;
  statusText: string;
  httpVersion: string;
  cookies: Cooky2[];
  headers: Header2[];
  content: Content;
  headersSize: number;
  bodySize: number;
  redirectURL: string;
}

export interface Cache {
  beforeRequest?: any;
  afterRequest?: any;
}

export interface Timings {
  dns: number;
  connect: number;
  ssl: number;
  send: number;
  wait: number;
  receive: number;
}

export interface Entry {
  pageref: string;
  startedDateTime: Date;
  time: number;
  request: Request;
  response: Response;
  cache: Cache;
  timings: Timings;
}

export interface Log {
  version: string;
  creator: Creator;
  browser: Browser;
  pages: Page[];
  entries: Entry[];
}

export interface Data {
  log: Log;
}

export interface HAR {
  data: Data;
}
