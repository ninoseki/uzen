<template>
  <div></div>
</template>

<script lang="ts">
import { defineComponent, PropType } from "@vue/composition-api";

import { ErrorData } from "@/types";

export default defineComponent({
  name: "Error",
  props: {
    error: {
      type: Object as PropType<ErrorData>,
      required: true,
    },
    backToRoute: {
      type: Boolean,
      default: false,
    },
  },
  setup(props, context) {
    const buildMessage = (error: ErrorData): string => {
      if (typeof error.detail === "string") {
        return error.detail;
      }

      const messages: string[] = [];
      for (const detail of error.detail) {
        const attr = detail.loc[detail.loc.length - 1];
        messages.push(`Validation error in ${attr} - ${detail.msg}`);
      }
      return messages.join("<br />");
    };

    const onConfirm = (): void => {
      if (props.backToRoute) {
        context.root.$router.push({ path: "/" });
      }
    };

    const alertError = () => {
      // if something goes wrong, the app returns a string (e.g Internal Server Error).
      let error = props.error;
      if (typeof error === "string") {
        error = { detail: error };
      }
      error = error as ErrorData;
      const message = buildMessage(error);

      context.root.$buefy.dialog.alert({
        title: "Error",
        message: message,
        type: "is-danger",
        ariaRole: "alertdialog",
        ariaModal: true,
        onConfirm,
      });
    };

    alertError();
  },
});
</script>
