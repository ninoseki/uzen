<template>
  <SnapshotJob :jobId="jobId" />
</template>

<script lang="ts">
import { defineComponent } from "vue";
import { useRoute } from "vue-router";

import SnapshotJob from "@/components/job/SnapshotJobWrapper.vue";

export default defineComponent({
  name: "SnapshotJobView",
  components: {
    SnapshotJob,
  },
  setup() {
    const route = useRoute();
    const jobId = route.params.id as string;

    return { jobId };
  },
});
</script>
