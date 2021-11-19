<template>
  <div>
    <Loading v-if="getSnapshotTask.isRunning"></Loading>
    <Error
      :backToRoute="true"
      :error="getSnapshotTask.last?.error.response.data"
      v-else-if="getSnapshotTask.isError"
    ></Error>

    <SnapshotComponent
      v-if="getSnapshotTask.last?.value && !getSnapshotTask.isError"
      :snapshot="getSnapshotTask.last.value"
      :yaraResult="yaraResult"
    ></SnapshotComponent>
  </div>
</template>

<script lang="ts">
import { useTitle } from "@vueuse/core";
import { defineComponent, PropType } from "vue";
import { useAsyncTask } from "vue-concurrency";

import { API } from "@/api";
import SnapshotComponent from "@/components/snapshot/Snapshot.vue";
import Error from "@/components/ui/SimpleError.vue";
import Loading from "@/components/ui/SimpleLoading.vue";
import { Snapshot, YaraResult } from "@/types";
import { countryCodeToEmoji } from "@/utils/country";

export default defineComponent({
  name: "SnapshotWrapper",
  components: {
    Error,
    Loading,
    SnapshotComponent,
  },
  props: {
    snapshotId: {
      type: String,
      required: true,
    },
    yaraResult: {
      type: Object as PropType<YaraResult>,
      required: false,
    },
  },

  setup(props) {
    // update title
    const updateTitle = (url: string): void => {
      useTitle(`${url} - Uzen`);
    };

    // get snapshot
    const getSnapshotTask = useAsyncTask<Snapshot, []>(async () => {
      return await API.getSnapshot(props.snapshotId);
    });

    const getSnapshot = async () => {
      const snapshot = await getSnapshotTask.perform();
      updateTitle(snapshot.url);
    };

    getSnapshot();

    return {
      countryCodeToEmoji,
      getSnapshotTask,
    };
  },
});
</script>
