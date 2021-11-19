<template>
  <Configuration />
</template>

<script lang="ts">
import { defineComponent } from "vue";

import Configuration from "@/components/Configuration.vue";

export default defineComponent({
  name: "ConfigurationView",
  components: {
    Configuration,
  },
});
</script>
