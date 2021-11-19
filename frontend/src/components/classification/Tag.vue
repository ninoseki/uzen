<template>
  <div :class="type" class="tag is-medium">
    {{ classification.name }}
    <span v-if="classification.note"> ({{ classification.note }}) </span>
  </div>
</template>

<script lang="ts">
import { computed, defineComponent, PropType } from "vue";

import { Classification } from "@/types";

export default defineComponent({
  name: "ClassificationButton",
  props: {
    classification: {
      type: Object as PropType<Classification>,
      required: true,
    },
  },
  setup(props) {
    const type = computed(() => {
      return props.classification.malicious ? "is-danger" : "is-success";
    });

    return { type };
  },
});
</script>
