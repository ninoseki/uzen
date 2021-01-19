<template>
  <Snapshot :snapshotId="$route.params.id" :yaraResult="yaraResult" />
</template>

<script lang="ts">
import { defineComponent, PropType } from "@vue/composition-api";

import Snapshot from "@/components/snapshot/Snapshot.vue";
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
});
</script>
