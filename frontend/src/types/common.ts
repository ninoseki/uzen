export interface ValidationError {
  loc: string[];
  msg: string;
  type: string;
}

export interface ErrorData {
  detail: string | ValidationError[];
}

export interface CountResponse {
  count: number;
}
