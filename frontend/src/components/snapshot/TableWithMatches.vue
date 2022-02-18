<template>
  <div v-if="hasSnapshots" ref="root">
    <table class="table is-fullwidth">
      <thead>
        <tr>
          <th>URL</th>
          <th>Created at</th>
          <th>Matches</th>
        </tr>
      </thead>
      <tbody>
        <tr v-for="snapshot in snapshots" :key="snapshot.id">
          <td>
            <URL :snapshot="snapshot"></URL>
          </td>
          <td>
            <DatetimeWithDiff :datetime="snapshot.createdAt" />
          </td>
          <td>
            <pre><code class="json">{{ snapshot.yaraResult?.matches }}</code></pre>
          </td>
        </tr>
      </tbody>
    </table>
  </div>
</template>

<script lang="ts">
import { computed, defineComponent, PropType, ref, watchEffect } from "vue";

import URL from "@/components/snapshot/table/URL.vue";
import DatetimeWithDiff from "@/components/ui/DatetimeWithDiff.vue";
import { SnapshotWithYaraResult } from "@/types/job";
import { highlightCodeBlocks } from "@/utils/highlight";

export default defineComponent({
  name: "SnapshotTableWithYaraResult",
  props: {
    snapshots: {
      type: Array as PropType<SnapshotWithYaraResult[]>,
      required: true,
    },
  },
  components: {
    DatetimeWithDiff,
    URL,
  },
  setup(props) {
    const root = ref<HTMLElement | null>(null);

    const hasSnapshots = computed((): boolean => {
      return props.snapshots.length > 0;
    });

    watchEffect(() => {
      if (root.value !== null) {
        highlightCodeBlocks(root.value);
      }
    });

    return { hasSnapshots, root };
  },
});
</script>
