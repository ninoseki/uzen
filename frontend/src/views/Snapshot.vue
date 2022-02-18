<template>
  <Snapshot :snapshotId="snapshotId" :yaraResult="yaraResult" />
</template>

<script lang="ts">
import { defineComponent, PropType } from "vue";
import { useRoute } from "vue-router";

import Snapshot from "@/components/snapshot/SnapshotWrapper.vue";
import { YaraResult } from "@/types";

export default defineComponent({
  name: "SnapshotView",
  components: {
    Snapshot,
  },
  props: {
    yaraResult: {
      type: Object as PropType<YaraResult>,
      required: false,
    },
  },
  setup() {
    const route = useRoute();
    const snapshotId = route.params.id as string;

    return { snapshotId };
  },
});
</script>
