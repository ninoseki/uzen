<template>
  <SimilarityScanJob :jobId="jobId" />
</template>

<script lang="ts">
import { defineComponent } from "vue";
import { useRoute } from "vue-router";

import SimilarityScanJob from "@/components/job/SimilarityScanJobWrapper.vue";

export default defineComponent({
  name: "SimilarityScanJobView",
  components: {
    SimilarityScanJob,
  },
  setup() {
    const route = useRoute();
    const jobId = route.params.id as string;

    return { jobId };
  },
});
</script>
