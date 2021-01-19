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
        name: 'Matches',
        query: { ruleId: ruleId },
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
import { MatchSearchResults } from "@/types";

export default defineComponent({
  name: "MatchesCounter",
  props: {
    ruleId: {
      type: String,
      required: true,
    },
  },
  setup(props) {
    const searchTask = useAsyncTask<MatchSearchResults, []>(async () => {
      const params = {
        size: 0,
        ruleId: props.ruleId,
      };
      return API.searchMatches(params);
    });

    searchTask.perform();

    return { searchTask };
  },
});
</script>
