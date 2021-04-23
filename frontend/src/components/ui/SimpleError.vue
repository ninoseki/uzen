<template>
  <b-message type="is-danger" has-icon>
    <ul>
      <li v-for="(message, index) in errorMessages" :key="index">
        {{ message }}
      </li>
    </ul>
  </b-message>
</template>

<script lang="ts">
import { computed, defineComponent, PropType } from "@vue/composition-api";

import { ErrorData } from "@/types";

export default defineComponent({
  name: "Error",
  props: {
    error: {
      type: Object as PropType<ErrorData>,
      required: true,
    },
  },
  setup(props) {
    const errorMessages = computed(() => {
      if (typeof props.error.detail === "string") {
        return [props.error.detail];
      }

      const messages: string[] = [];
      for (const detail of props.error.detail) {
        const attr = detail.loc[detail.loc.length - 1];
        messages.push(`Validation error in ${attr} - ${detail.msg}`);
      }
      return messages;
    });

    return { errorMessages };
  },
});
</script>
