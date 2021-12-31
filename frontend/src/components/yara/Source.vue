<template>
  <pre ref="root"><code class="yara">{{ source || "N/A" }}</code></pre>
</template>

<script lang="ts">
import { defineComponent, onMounted, ref } from "vue";

import { highlightCodeBlocks } from "@/utils/highlight";

export default defineComponent({
  name: "YaraSource",
  props: {
    source: {
      type: String,
      required: false,
    },
  },
  setup() {
    const root = ref<HTMLElement | null>(null);

    onMounted(() => {
      if (root.value !== null) {
        highlightCodeBlocks(root.value);
      }
    });

    return { root };
  },
});
</script>
