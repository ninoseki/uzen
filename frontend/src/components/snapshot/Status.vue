<template>
  <p class="has-text-grey-light has-text-right">
    You are going to take a snapshot from
    {{ countryCodeToEmoji(statusState.countryCode) }}
  </p>
</template>

<script lang="ts">
import { defineComponent, onMounted } from "vue";
import { useSessionStorage } from "@vueuse/core";

import { countryCodeToEmoji } from "@/utils/country";
import { generateGetStatusTask } from "@/api-helper";

export default defineComponent({
  name: "Status",
  setup() {
    const statusState = useSessionStorage("uzen-status", {
      ipAddress: "",
      countryCode: "",
    });

    const getStatusTask = generateGetStatusTask();

    onMounted(async () => {
      if (statusState.value.ipAddress === "") {
        const status = await getStatusTask.perform();

        statusState.value.ipAddress = status.ipAddress;
        statusState.value.countryCode = status.countryCode;
      }
    });

    return {
      countryCodeToEmoji,
      statusState,
    };
  },
});
</script>
