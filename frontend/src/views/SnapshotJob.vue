<template>
  <SnapshotJob :jobId="$route.params.id" />
</template>

<script lang="ts">
import { defineComponent } from "@vue/composition-api";

import SnapshotJob from "@/components/job/SnapshotJobWrapper.vue";

export default defineComponent({
  name: "SnapshotJobView",
  components: {
    SnapshotJob,
  },
});
</script>
