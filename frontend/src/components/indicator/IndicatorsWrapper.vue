<template>
  <div>
    <Loading v-if="getIndicatorsTask.isRunning"></Loading>
    <div
      v-else-if="!getIndicatorsTask.isError && getIndicatorsTask.last?.value"
    >
      <IndicatorsComponent :indicators="getIndicatorsTask.last.value" />
    </div>
    <NA v-else></NA>
  </div>
</template>

<script lang="ts">
import { defineComponent, onMounted } from "vue";

import IndicatorsComponent from "@/components/indicator/Indicators.vue";
import NA from "@/components/ui/NA.vue";
import Loading from "@/components/ui/SimpleLoading.vue";
import { generateGetIndicatorsTask } from "@/api-helper";

export default defineComponent({
  name: "IndicatorsWrapper",
  props: {
    snapshotId: {
      type: String,
      required: true,
    },
  },
  components: {
    IndicatorsComponent,
    NA,
    Loading,
  },
  setup(props) {
    const getIndicatorsTask = generateGetIndicatorsTask();

    onMounted(async () => {
      await getIndicatorsTask.perform(props.snapshotId);
    });

    return { getIndicatorsTask };
  },
});
</script>
