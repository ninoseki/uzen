<template>
  <div v-if="jobStatus.result !== null">
    <h2>{{ jobStatus.result.scanResults.length }} snapshots found</h2>
    <SnapshotTable
      :snapshots="jobStatus.result.scanResults || []"
    ></SnapshotTable>
  </div>
</template>

<script lang="ts">
import { defineComponent, PropType } from "vue";

import SnapshotTable from "@/components/snapshot/Table.vue";
import { SimilarityScanJobStatus } from "@/types";

export default defineComponent({
  name: "SimilarityScanJob",
  components: {
    SnapshotTable,
  },
  props: {
    jobStatus: {
      type: Object as PropType<SimilarityScanJobStatus>,
      required: true,
    },
  },
});
</script>
