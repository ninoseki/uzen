<template>
  <SimilarityScanJob :jobId="$route.params.id" />
</template>

<script lang="ts">
import { defineComponent } from "@vue/composition-api";

import SimilarityScanJob from "@/components/job/SimilarityScanJobWrapper.vue";

export default defineComponent({
  name: "SimilarityScanJobView",
  components: {
    SimilarityScanJob,
  },
});
</script>
