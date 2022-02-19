<template>
  <div>
    <Loading v-if="isLoading"></Loading>
    <pre v-else><code class="hljs" v-html="highlightedHTML"></code></pre>
  </div>
</template>

<script lang="ts">
import { defineComponent, onMounted, ref, watch } from "vue";

import Loading from "@/components/ui/SimpleLoading.vue";
import { highlightWorkerFn } from "@/utils/highlight.worker";

export default defineComponent({
  name: "CodeItem",
  props: {
    data: {
      type: String,
      required: true,
    },
  },
  components: {
    Loading,
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
      async () => {
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
