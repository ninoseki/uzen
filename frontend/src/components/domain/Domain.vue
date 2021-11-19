<template>
  <div class="box">
    <nav class="navbar">
      <div class="navbar-brand">
        <H2>Domain: {{ domain.hostname }}</H2>
      </div>
      <div class="navbar-menu">
        <div class="navbar-end">
          <Links :hostname="domain.hostname" type="domain" />
        </div>
      </div>
    </nav>

    <div class="column is-full">
      <div class="columns">
        <div class="column is-half">
          <H3> DNS records </H3>
          <DnsRecords :dnsRecords="domain.dnsRecords" />
        </div>
        <div class="column is-half">
          <H3> Live preview </H3>
          <Preview :hostname="domain.hostname" />
        </div>
      </div>
    </div>

    <div class="column">
      <H3>
        Recent snapshots
        <Counter :hostname="domain.hostname" />
      </H3>

      <Table v-if="hasSnapshots" :snapshots="domain.snapshots" />
      <p v-else>N/A</p>
    </div>

    <div class="column">
      <H3> Whois </H3>
      <Whois :whois="domain.whois" v-if="domain.whois"></Whois>
    </div>
  </div>
</template>

<script lang="ts">
import { computed, defineComponent, PropType } from "vue";

import DnsRecords from "@/components/dns_record/DnsRecords.vue";
import Links from "@/components/link/Links.vue";
import Preview from "@/components/screenshot/Preview.vue";
import Counter from "@/components/snapshot/Counter.vue";
import Table from "@/components/snapshot/TableWithScreenshot.vue";
import H2 from "@/components/ui/H2.vue";
import H3 from "@/components/ui/H3.vue";
import Whois from "@/components/whois/Whois.vue";
import { DomainInformation } from "@/types";

export default defineComponent({
  name: "Domain",
  components: {
    Counter,
    DnsRecords,
    H2,
    H3,
    Links,
    Preview,
    Table,
    Whois,
  },
  props: {
    domain: {
      type: Object as PropType<DomainInformation>,
      required: true,
    },
  },
  setup(props) {
    const hasSnapshots = computed(() => {
      return (props.domain.snapshots.length || 0) > 0;
    });

    return { hasSnapshots };
  },
});
</script>
