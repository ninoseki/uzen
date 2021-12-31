<template>
  <span
    v-if="
      !searchTask.isRunning && searchTask.last?.value && !searchTask.isError
    "
  >
    (
    <router-link
      :to="{
        name: 'Snapshots',
        query: { hostname: hostname, ipAddress: ipAddress },
      }"
      >{{ searchTask.last.value.total }} in total
    </router-link>
    )</span
  >
</template>

<script lang="ts">
import { defineComponent, onMounted } from "vue";

import { generateSearchSnapshotsTask } from "@/api-helper";

export default defineComponent({
  name: "SnapshotsCounter",
  props: {
    hostname: String,
    ipAddress: String,
  },
  setup(props) {
    const searchTask = generateSearchSnapshotsTask();

    const search = async () => {
      const params = {
        size: 0,
        hostname: props.hostname,
        ipAddress: props.ipAddress,
      };
      return searchTask.perform(params);
    };

    onMounted(async () => {
      await search();
    });

    return { searchTask };
  },
});
</script>
