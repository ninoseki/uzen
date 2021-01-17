<template>
  <Search :ruleId="$route.query.ruleId" :snapshotId="$route.query.snapshotId" />
</template>

<script lang="ts">
import { defineComponent } from "@vue/composition-api";

import Search from "@/components/matches/Search.vue";

export default defineComponent({
  name: "MatchesView",
  components: {
    Search,
  },
});
</script>
