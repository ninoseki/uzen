import dayjs from "dayjs";
import relativeTime from "dayjs/plugin/relativeTime";
import timezone from "dayjs/plugin/timezone";
import utc from "dayjs/plugin/utc";

dayjs.extend(relativeTime);
dayjs.extend(timezone);
dayjs.extend(utc);

export const DEFAULT_PAGE_SIZE = 10;
export const DEFAULT_OFFSET = 0;

export function hasLoadMore(
  count: number | undefined,
  total: number | undefined
): boolean {
  count = count || 0;
  total = total || 0;

  return count < total;
}

export function normalizeFilterValue(
  value: string | number | Date
): string | number | undefined {
  if (value instanceof Date) {
    return value.toISOString();
  }
  if (typeof value === "string") {
    // returns undefined if a value is an empty string
    return value === "" ? undefined : value;
  }
  return value;
}

export function nowDatetime(): string {
  return dayjs().toISOString();
}

export function minDatetime(
  a: string | number | undefined,
  b: string | number | undefined
): string {
  const c = a === undefined ? dayjs() : dayjs(a);
  const d = b === undefined ? dayjs() : dayjs(b);

  return c > d ? d.toISOString() : c.toISOString();
}
