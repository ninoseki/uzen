<template>
  <div>
    <div v-if="getHARTask.last && getHARTask.last.value && !getHARTask.isError">
      <pre><code class="json">{{ getHARTask.last.value.data }}</code></pre>
    </div>
    <NA v-else></NA>
  </div>
</template>

<script lang="ts">
import { defineComponent, onUpdated } from "@vue/composition-api";
import { useAsyncTask } from "vue-concurrency";

import { API } from "@/api";
import NA from "@/components/ui/NA.vue";
import { HAR } from "@/types";
import { highlightCodeBlocks } from "@/utils/highlight";

export default defineComponent({
  name: "HAR",
  components: { NA },
  props: {
    snapshotId: {
      type: String,
      required: true,
    },
  },
  setup(props, context) {
    const getHARTask = useAsyncTask<HAR, []>(async () => {
      return await API.getHAR(props.snapshotId);
    });

    getHARTask.perform();

    onUpdated(() => {
      highlightCodeBlocks(context);
    });

    return { getHARTask };
  },
});
</script>
