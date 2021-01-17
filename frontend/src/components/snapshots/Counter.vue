<template>
  <span
    v-if="
      !searchTask.isRunning &&
      searchTask.last &&
      searchTask.last.value &&
      !searchTask.isError
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
import { defineComponent } from "@vue/composition-api";
import { useAsyncTask } from "vue-concurrency";

import { API } from "@/api";
import { SnapshotSearchResults } from "@/types";

export default defineComponent({
  name: "SnapshotsCounter",
  props: {
    hostname: String,
    ipAddress: String,
  },
  setup(props) {
    const searchTask = useAsyncTask<SnapshotSearchResults, []>(async () => {
      const options = {
        size: 0,
        hostname: props.hostname,
        ipAddress: props.ipAddress,
      };
      return API.searchSnapshots(options);
    });

    searchTask.perform();

    return { searchTask };
  },
});
</script>
