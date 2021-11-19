<template>
  <div class="box">
    <nav class="navbar">
      <div class="navbar-brand">
        <H2
          >IP address: {{ ipAddress.ipAddress }}
          {{ countryCodeToEmoji(ipAddress.countryCode) }}</H2
        >
      </div>
      <div class="navbar-menu">
        <div class="navbar-end">
          <Links v-bind:ipAddress="ipAddress.ipAddress" type="ip_address" />
        </div>
      </div>
    </nav>

    <div class="column is-full">
      <div class="columns">
        <div class="column is-half">
          <H3>Basic information</H3>
          <div class="table-container">
            <table class="table is-completely-borderless">
              <tbody>
                <tr>
                  <th>ASN</th>
                  <td>{{ ipAddress.asn }}</td>
                </tr>
                <tr>
                  <th>Description</th>
                  <td>{{ ipAddress.description }}</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
        <div class="column is-half">
          <H3>Live preview</H3>
          <Preview v-bind:hostname="ipAddress.ipAddress" />
        </div>
      </div>
    </div>

    <div class="column">
      <H3>
        Recent snapshots
        <Counter v-bind:ipAddress="ipAddress.ipAddress" />
      </H3>
      <ScreenshotTable
        v-if="hasSnapshots"
        v-bind:snapshots="ipAddress.snapshots"
      />
      <p v-else>N/A</p>
    </div>

    <div class="column">
      <H3> Whois </H3>
      <Whois :whois="ipAddress.whois" v-if="ipAddress.whois"></Whois>
    </div>
  </div>
</template>

<script lang="ts">
import { computed, defineComponent, PropType } from "vue";

import Links from "@/components/link/Links.vue";
import Preview from "@/components/screenshot/Preview.vue";
import Counter from "@/components/snapshot/Counter.vue";
import ScreenshotTable from "@/components/snapshot/TableWithScreenshot.vue";
import H2 from "@/components/ui/H2.vue";
import H3 from "@/components/ui/H3.vue";
import Whois from "@/components/whois/Whois.vue";
import { IPAddressInformation } from "@/types";
import { countryCodeToEmoji } from "@/utils/country";

export default defineComponent({
  name: "IPAddress",
  components: {
    Counter,
    H2,
    H3,
    Links,
    Preview,
    ScreenshotTable,
    Whois,
  },
  props: {
    ipAddress: {
      type: Object as PropType<IPAddressInformation>,
      required: true,
    },
  },
  setup(props) {
    const hasSnapshots = computed(() => {
      return (props.ipAddress.snapshots.length || 0) > 0;
    });

    return { hasSnapshots, countryCodeToEmoji };
  },
});
</script>

<style scoped>
.table img {
  width: 180px;
}
</style>
