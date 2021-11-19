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
import { defineComponent } from "vue";
import { useAsyncTask } from "vue-concurrency";
import { useRoute } from "vue-router";

import { API } from "@/api";
import IPAddress from "@/components/ip_address/IPAddress.vue";
import Error from "@/components/ui/SimpleError.vue";
import Loading from "@/components/ui/SimpleLoading.vue";
import { IPAddressInformation } from "@/types";

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

    const getIPAddressTask = useAsyncTask<IPAddressInformation, []>(
      async () => {
        return API.getIPAddressInformation(hostname);
      }
    );

    getIPAddressTask.perform();

    return { getIPAddressTask };
  },
});
</script>
