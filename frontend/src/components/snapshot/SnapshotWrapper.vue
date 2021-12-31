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
import { defineComponent, onMounted, PropType } from "vue";

import SnapshotComponent from "@/components/snapshot/Snapshot.vue";
import Error from "@/components/ui/SimpleError.vue";
import Loading from "@/components/ui/SimpleLoading.vue";
import { YaraResult } from "@/types";
import { countryCodeToEmoji } from "@/utils/country";
import { generateGetSnapshotTask } from "@/api-helper";

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

    const getSnapshotTask = generateGetSnapshotTask();

    const getSnapshot = async () => {
      return await getSnapshotTask.perform(props.snapshotId);
    };

    onMounted(async () => {
      const snapshot = await getSnapshot();
      updateTitle(snapshot.url);
    });

    return {
      countryCodeToEmoji,
      getSnapshotTask,
    };
  },
});
</script>
