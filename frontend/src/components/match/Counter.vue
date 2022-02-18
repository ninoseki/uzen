<template>
  <span
    v-if="
      !searchTask.isRunning && searchTask.last?.value && !searchTask.isError
    "
  >
    (
    <router-link
      :to="{
        name: 'Matches',
        query: { ruleId: ruleId },
      }"
      >{{ searchTask.last.value.total }} in total
    </router-link>
    )</span
  >
</template>

<script lang="ts">
import { defineComponent, onMounted } from "vue";

import { generateSearchMatchesTask } from "@/api-helper";

export default defineComponent({
  name: "MatchesCounter",
  props: {
    ruleId: {
      type: String,
      required: true,
    },
  },
  setup(props) {
    const searchTask = generateSearchMatchesTask();

    const search = async () => {
      const params = {
        size: 0,
        ruleId: props.ruleId,
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
