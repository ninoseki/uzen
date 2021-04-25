<template>
  <div v-if="jobStatus.result !== null">
    <h2>{{ jobStatus.result.scanResults.length }} snapshots found</h2>
    <SnapshotTable
      :snapshots="jobStatus.result.scanResults || []"
    ></SnapshotTable>
  </div>
</template>

<script lang="ts">
import { defineComponent, PropType } from "@vue/composition-api";

import SnapshotTable from "@/components/snapshot/Table.vue";
import { YaraScanJobStatus } from "@/types";

export default defineComponent({
  name: "YaraScanJob",
  components: {
    SnapshotTable,
  },
  props: {
    jobStatus: {
      type: Object as PropType<YaraScanJobStatus>,
      required: true,
    },
  },
});
</script>
