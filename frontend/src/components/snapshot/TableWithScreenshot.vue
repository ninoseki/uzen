<template>
  <div v-if="hasSnapshots">
    <table class="table is-fullwidth">
      <thead>
        <tr>
          <th>URL</th>
          <th>Created at</th>
          <th>Screenshot</th>
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
            <Screenshot :snapshotId="snapshot.id" />
          </td>
        </tr>
      </tbody>
    </table>
  </div>
</template>

<script lang="ts">
import { computed, defineComponent, PropType } from "vue";

import Screenshot from "@/components/screenshot/Screenshot.vue";
import URL from "@/components/snapshot/table/URL.vue";
import DatetimeWithDiff from "@/components/ui/DatetimeWithDiff.vue";
import { Snapshot } from "@/types";

export default defineComponent({
  name: "SnapshotTableWithScreenshot",
  props: {
    snapshots: {
      type: Array as PropType<Snapshot[]>,
      required: true,
    },
  },
  components: {
    DatetimeWithDiff,
    Screenshot,
    URL,
  },
  setup(props) {
    const hasSnapshots = computed((): boolean => {
      return props.snapshots.length > 0;
    });

    return { hasSnapshots };
  },
});
</script>

<style>
.table img {
  max-width: 180px;
}
</style>
