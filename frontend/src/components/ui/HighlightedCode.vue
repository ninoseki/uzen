<template>
  <pre><code class="hljs" v-html="highlightedHTML"></code></pre>
</template>

<script lang="ts">
import { defineComponent, onMounted, ref, watch } from "@vue/composition-api";

import { highlightWorkerFn } from "@/utils/highlight.worker";

export default defineComponent({
  name: "Code",
  props: {
    data: {
      type: String,
      required: true,
    },
  },
  setup(props) {
    const highlightedHTML = ref("");

    const highlight = async () => {
      highlightedHTML.value = "";
      highlightedHTML.value = await highlightWorkerFn(props.data);
    };

    onMounted(async () => {
      await highlight();
    });

    watch(
      () => props.data,
      // eslint-disable-next-line no-unused-vars
      async (_first, _second) => {
        highlight();
      }
    );

    return {
      highlightedHTML,
    };
  },
});
</script>

<style scoped>
pre {
  background-color: #282b2e;
}
</style>
