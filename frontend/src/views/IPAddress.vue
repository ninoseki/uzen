<template>
  <IPAddress />
</template>

<script lang="ts">
import { useTitle } from "@vueuse/core";
import { defineComponent } from "vue";
import { useRoute } from "vue-router";

import IPAddress from "@/components/ip_address/IPAddressWrapper.vue";

export default defineComponent({
  name: "IPAddressView",
  components: {
    IPAddress,
  },
  setup() {
    const route = useRoute();

    const updateTitle = (): void => {
      const ipAddress = route.params.ipAddress;
      useTitle(`${ipAddress} - Uzen`);
    };

    updateTitle();
  },
});
</script>
