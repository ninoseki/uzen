<template>
  <IPAddress />
</template>

<script lang="ts">
import { Component, Vue } from "vue-property-decorator";

import IPAddress from "@/components/ip_address/IPAddress.vue";

@Component({
  components: {
    IPAddress,
  },
})
export default class IPAddressView extends Vue {}
</script>
