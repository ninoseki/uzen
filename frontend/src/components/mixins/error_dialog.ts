import Vue from "vue";
import { Mixin } from "vue-mixin-decorator";

import { ErrorData } from "@/types";

@Mixin
export class ErrorDialogMixin extends Vue {
  buildMessage(error: ErrorData): string {
    if (typeof error.detail === "string") {
      return error.detail;
    }

    const messages: string[] = [];
    for (const detail of error.detail) {
      const attr = detail.loc[detail.loc.length - 1];
      const message = `${attr} ${detail.msg}`;
      messages.push(message);
    }
    return messages.join("<br />");
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
