<template>
  <div>
    <div v-if="getHARTask.isRunning">Loading...</div>
    <div
      v-else-if="
        getHARTask.last && getHARTask.last.value && !getHARTask.isError
      "
    >
      <HARComponent
        :har="getHARTask.last.value"
        :snapshotId="snapshotId"
      ></HARComponent>
    </div>
    <NA v-else></NA>
  </div>
</template>

<script lang="ts">
import { defineComponent } from "@vue/composition-api";
import { useAsyncTask } from "vue-concurrency";

import { API } from "@/api";
import HARComponent from "@/components/har/HAR.vue";
import NA from "@/components/ui/NA.vue";
import { HAR } from "@/types";

export default defineComponent({
  name: "HARWrapper",
  components: { HARComponent, NA },
  props: {
    snapshotId: {
      type: String,
      required: true,
    },
  },
  setup(props) {
    const getHARTask = useAsyncTask<HAR, []>(async () => {
      return await API.getHAR(props.snapshotId);
    });

    getHARTask.perform();

    return { getHARTask };
  },
});
</script>
