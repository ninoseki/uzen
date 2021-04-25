<template>
  <YaraScanJob :jobId="$route.params.id" />
</template>

<script lang="ts">
import { defineComponent } from "@vue/composition-api";

import YaraScanJob from "@/components/job/YaraScanJobWrapper.vue";

export default defineComponent({
  name: "YaraScanJobView",
  components: {
    YaraScanJob,
  },
});
</script>
