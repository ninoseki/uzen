<template>
  <Search />
</template>

<script lang="ts">
import { defineComponent } from "@vue/composition-api";

import Search from "@/components/snapshots/Search.vue";

export default defineComponent({
  name: "SearchView",
  components: {
    Search,
  },
});
</script>
