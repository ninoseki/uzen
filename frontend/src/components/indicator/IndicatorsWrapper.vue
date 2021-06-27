<template>
  <div>
    <div v-if="getIndicatorsTask.isRunning">Loading...</div>
    <div
      v-else-if="
        !getIndicatorsTask.isError &&
        getIndicatorsTask.last &&
        getIndicatorsTask.last.value
      "
    >
      <IndicatorsComponent :indicators="getIndicatorsTask.last.value" />
    </div>
    <NA v-else></NA>
  </div>
</template>

<script lang="ts">
import { defineComponent } from "@vue/composition-api";
import { useAsyncTask } from "vue-concurrency";

import { API } from "@/api";
import IndicatorsComponent from "@/components/indicator/Indicators.vue";
import NA from "@/components/ui/NA.vue";
import { Indicators } from "@/types";

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
  },
  setup(props) {
    const getIndicatorsTask = useAsyncTask<Indicators, []>(async () => {
      return await API.getIndicators(props.snapshotId);
    });

    getIndicatorsTask.perform();

    return { getIndicatorsTask };
  },
});
</script>
