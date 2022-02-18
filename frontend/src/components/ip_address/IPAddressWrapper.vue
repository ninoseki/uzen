<template>
  <div>
    <Loading v-if="getIPAddressTask.isRunning"></Loading>
    <Error
      :error="getIPAddressTask.last.error.response.data"
      v-else-if="getIPAddressTask.isError && getIPAddressTask.last"
    ></Error>
    <IPAddress
      v-else-if="getIPAddressTask.last?.value && !getIPAddressTask.isError"
      :ipAddress="getIPAddressTask.last.value"
    ></IPAddress>
  </div>
</template>

<script lang="ts">
import { defineComponent, onMounted } from "vue";
import { useRoute } from "vue-router";

import IPAddress from "@/components/ip_address/IPAddress.vue";
import Error from "@/components/ui/SimpleError.vue";
import Loading from "@/components/ui/SimpleLoading.vue";
import { generateGetIPAddressTask } from "@/api-helper";

export default defineComponent({
  name: "IPAddressWrapper",
  components: {
    Error,
    Loading,
    IPAddress,
  },
  setup() {
    const route = useRoute();
    const hostname = route.params.ipAddress as string;

    const getIPAddressTask = generateGetIPAddressTask();

    onMounted(async () => {
      await getIPAddressTask.perform(hostname);
    });

    return { getIPAddressTask };
  },
});
</script>
