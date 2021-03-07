<template>
  <div>
    <Loading v-if="getIPAddressTask.isRunning"></Loading>

    <Error
      :backToRoute="true"
      :error="getIPAddressTask.last.error.response.data"
      v-else-if="
        getIPAddressTask.isError && getIPAddressTask.last !== undefined
      "
    ></Error>

    <IPAddress
      v-else-if="
        getIPAddressTask.last &&
        getIPAddressTask.last.value &&
        !getIPAddressTask.isError
      "
      :ipAddress="getIPAddressTask.last.value"
    ></IPAddress>
  </div>
</template>

<script lang="ts">
import { defineComponent } from "@vue/composition-api";
import { useAsyncTask } from "vue-concurrency";

import { API } from "@/api";
import IPAddress from "@/components/ip_address/IPAddress.vue";
import Error from "@/components/ui/Error.vue";
import Loading from "@/components/ui/Loading.vue";
import { IPAddressInformation } from "@/types";

export default defineComponent({
  name: "IPAddressWrapper",
  components: {
    Error,
    Loading,
    IPAddress,
  },
  setup(_, context) {
    const hostname = context.root.$route.params.ipAddress;

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
