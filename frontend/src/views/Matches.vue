<template>
  <Search :ruleId="ruleId" :snapshotId="snapshotId" />
</template>

<script lang="ts">
import { useRouteQuery } from "@vueuse/router";
import { defineComponent, Ref } from "vue";
import { useRoute, useRouter } from "vue-router";

import Search from "@/components/match/Search.vue";

export default defineComponent({
  name: "MatchesView",
  components: {
    Search,
  },
  setup() {
    const route = useRoute();
    const router = useRouter();
    const options = { route, router };

    const ruleId = useRouteQuery("ruleId", "", options) as Ref<string>;
    const snapshotId = useRouteQuery("snapshotId", "", options) as Ref<string>;

    return { ruleId, snapshotId };
  },
});
</script>
