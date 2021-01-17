<template>
  <Import />
</template>

<script lang="ts">
import { defineComponent } from "@vue/composition-api";

import Import from "@/components/Import.vue";

export default defineComponent({
  name: "ImportView",
  components: { Import },
});
</script>
