export interface Viewport {
  width: number;
  height: number;
}

export interface Descriptor {
  userAgent: string;
  viewport: Viewport;
  deviceScaleFactor: number;
  isMobile: boolean;
  hasTouch: boolean;
}

export interface Device {
  name: string;
  descriptor: Descriptor;
}
