<template>
  <pre><code class="yara">{{ source || "N/A" }}</code></pre>
</template>

<script lang="ts">
import { defineComponent, onMounted } from "@vue/composition-api";

import { highlightCodeBlocks } from "@/utils/highlight";

export default defineComponent({
  name: "YaraSoure",
  props: {
    source: {
      type: String,
      required: false,
    },
  },
  setup(_, context) {
    onMounted(async () => {
      highlightCodeBlocks(context);
    });
  },
});
</script>
