<template>
  <div>
    <b-progress size="is-medium" show-value v-if="isLoading">
      Loading...
    </b-progress>
    <pre v-else><code class="hljs" v-html="highlightedHTML"></code></pre>
  </div>
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
    const isLoading = ref(true);

    const highlight = async () => {
      highlightedHTML.value = "";
      highlightedHTML.value = await highlightWorkerFn(props.data);
    };

    onMounted(async () => {
      await highlight();

      isLoading.value = false;
    });

    watch(
      () => props.data,
      // eslint-disable-next-line no-unused-vars
      async (_first, _second) => {
        isLoading.value = true;

        await highlight();

        isLoading.value = false;
      }
    );

    return {
      isLoading,
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
