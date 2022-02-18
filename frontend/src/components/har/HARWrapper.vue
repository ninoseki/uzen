<template>
  <div>
    <Loading v-if="getHARTask.isRunning"></Loading>
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
import { defineComponent, onMounted } from "vue";

import HARComponent from "@/components/har/HAR.vue";
import NA from "@/components/ui/NA.vue";
import Loading from "@/components/ui/SimpleLoading.vue";
import { generateGetHARTask } from "@/api-helper";

export default defineComponent({
  name: "HARWrapper",
  components: { HARComponent, NA, Loading },
  props: {
    snapshotId: {
      type: String,
      required: true,
    },
  },
  setup(props) {
    const getHARTask = generateGetHARTask();

    onMounted(async () => {
      await getHARTask.perform(props.snapshotId);
    });

    return { getHARTask };
  },
});
</script>
