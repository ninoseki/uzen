<template>
  <pre><code class="html">{{ html }}</code></pre>
</template>

<script lang="ts">
import { defineComponent, onMounted } from "@vue/composition-api";

import { highlightCodeBlocks } from "@/utils/highlight";

export default defineComponent({
  name: "HTML",
  props: {
    html: {
      type: String,
      required: true,
    },
  },
  setup(_, context) {
    onMounted(() => {
      highlightCodeBlocks(context);
    });
  },
});
</script>
