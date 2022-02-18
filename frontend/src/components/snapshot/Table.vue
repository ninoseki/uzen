<template>
  <div class="box table-container" v-if="$props.snapshots.length > 0">
    <table class="table is-fullwidth">
      <thead>
        <tr>
          <th>URL</th>
          <th>Created at</th>
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
        </tr>
      </tbody>
    </table>
  </div>
</template>

<script lang="ts">
import { defineComponent, PropType } from "vue";

import URL from "@/components/snapshot/table/URL.vue";
import DatetimeWithDiff from "@/components/ui/DatetimeWithDiff.vue";
import {
  Snapshot,
  SnapshotWithSimilarity,
  SnapshotWithYaraResult,
} from "@/types";

export default defineComponent({
  name: "SnapshotTable",
  props: {
    snapshots: {
      type: Array as PropType<
        Snapshot[] | SnapshotWithYaraResult[] | SnapshotWithSimilarity[]
      >,
      required: true,
    },
  },
  components: {
    DatetimeWithDiff,
    URL,
  },
});
</script>
