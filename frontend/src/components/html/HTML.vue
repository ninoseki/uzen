<template>
  <HighlightedCode :data="html"></HighlightedCode>
</template>

<script lang="ts">
import { defineComponent } from "vue";

import HighlightedCode from "@/components/ui/HighlightedCode.vue";

export default defineComponent({
  name: "HTML",
  props: {
    html: {
      type: String,
      required: true,
    },
  },
  components: {
    HighlightedCode,
  },
});
</script>
