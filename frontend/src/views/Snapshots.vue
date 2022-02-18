<template>
  <Search />
</template>

<script lang="ts">
import { defineComponent } from "vue";

import Search from "@/components/snapshot/Search.vue";

export default defineComponent({
  name: "SearchView",
  components: {
    Search,
  },
});
</script>
