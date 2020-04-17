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

  dateFormatter(dt: Date): string {
    return dt.toISOString().split("T")[0];
  }

  normalizeFilterValue(value: string | number | Date): string | number {
    if (value instanceof Date) {
      return value.toISOString().split("T")[0];
    }
    return value;
  }
}
