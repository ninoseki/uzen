import Vue from "vue";
import { Mixin } from "vue-mixin-decorator";

import hljs from "highlight.js/lib/highlight.js";
import json from "highlight.js/lib/languages/json";
import xml from "highlight.js/lib/languages/xml";
// register highlight languages
hljs.registerLanguage("json", json);
hljs.registerLanguage("xml", xml);

import { ErrorData } from "@/types";

@Mixin
export class ErrorDialogMixin extends Vue {
  buildMessage(error: ErrorData): string {
    if (typeof error.detail === "string") {
      return error.detail;
    }

    if (error.detail.length > 0) {
      return error.detail[0].msg;
    }
    return "";
  }

  alertError(error: ErrorData) {
    const message = this.buildMessage(error);

    this.$buefy.dialog.alert({
      title: "Error",
      message: message,
      type: "is-danger",
      ariaRole: "alertdialog",
      ariaModal: true,
    });
  }
}

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
}

export interface SearchFormComponentMixin
  extends SearchFormMixin,
    ErrorDialogMixin {}

@Mixin
export class HighlightMixin extends Vue {
  highlightCodeBlocks() {
    if (this.$el.textContent === "") {
      // do nothing when $el is empty
      return;
    }

    this.$el.querySelectorAll("pre code").forEach((block) => {
      hljs.highlightBlock(block);
    });
  }
}
