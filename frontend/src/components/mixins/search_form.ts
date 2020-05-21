import moment from "moment/moment";
import Vue from "vue";
import { Mixin } from "vue-mixin-decorator";

@Mixin
export class SearchFormMixin extends Vue {
  DEFAULT_PAGE_SIZE = 10;
  DEFAULT_OFFSET = 0;

  count: number | undefined = undefined;
  totalCount: number = 0;
  size = this.DEFAULT_PAGE_SIZE;
  offset = this.DEFAULT_OFFSET;

  hasCount(): boolean {
    return this.count !== undefined;
  }

  hasLoadMore() {
    const count = this.count || 0;
    const total = this.totalCount || 0;

    return count < total;
  }

  normalizeFilterValue(
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

  datetimeFormatter(datetime: Date): string {
    return moment.parseZone(datetime).local().format();
  }
}
