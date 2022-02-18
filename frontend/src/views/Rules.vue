<template>
  <Search />
</template>

<script lang="ts">
import { defineComponent } from "vue";

import Search from "@/components/rule/Search.vue";

export default defineComponent({
  name: "RulesView",
  components: {
    Search,
  },
});
</script>
