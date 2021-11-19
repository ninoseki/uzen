<template>
  <p
    class="has-text-grey-light has-text-right"
    v-if="getStatusTask.last?.value"
  >
    You are going to take a snapshot from
    {{ countryCodeToEmoji(getStatusTask.last.value.countryCode) }}
  </p>
</template>

<script lang="ts">
import { defineComponent, onMounted } from "vue";
import { useAsyncTask } from "vue-concurrency";

import { API } from "@/api";
import { Status } from "@/types";
import { countryCodeToEmoji } from "@/utils/country";

export default defineComponent({
  name: "Status",
  setup() {
    const getStatusTask = useAsyncTask<Status, []>(async () => {
      return API.getStatus();
    });

    onMounted(async () => {
      await getStatusTask.perform();
    });

    return {
      countryCodeToEmoji,
      getStatusTask,
    };
  },
});
</script>
