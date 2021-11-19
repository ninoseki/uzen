<template>
  <YaraScanJob :jobId="jobId" />
</template>

<script lang="ts">
import { defineComponent } from "vue";
import { useRoute } from "vue-router";

import YaraScanJob from "@/components/job/YaraScanJobWrapper.vue";

export default defineComponent({
  name: "YaraScanJobView",
  components: {
    YaraScanJob,
  },
  setup() {
    const route = useRoute();
    const jobId = route.params.id as string;

    return { jobId };
  },
});
</script>
