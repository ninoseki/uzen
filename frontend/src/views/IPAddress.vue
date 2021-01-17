<template>
  <IPAddress />
</template>

<script lang="ts">
import { defineComponent } from "@vue/composition-api";

import IPAddress from "@/components/ip_address/IPAddress.vue";

export default defineComponent({
  name: "IPAddressView",
  components: {
    IPAddress,
  },
  setup(_, { root }) {
    const updateTitle = (): void => {
      const ipAddress = root.$route.params.ipAddress;
      document.title = `${ipAddress} - Uzen`;
    };

    updateTitle();
  },
});
</script>
