<template>
  <b-table :data="dnsRecords">
    <template slot-scope="props">
      <b-table-column field="type" label="Type">
        {{ props.row.type }}
      </b-table-column>

      <b-table-column field="value" label="Value">
        {{ props.row.value }}
      </b-table-column>
    </template>
  </b-table>
</template>

<script lang="ts">
import { Component, Vue, Prop } from "vue-property-decorator";

import { DnsRecord } from "@/types";

@Component
export default class DnsRecords extends Vue {
  @Prop() private dnsRecords!: DnsRecord[];
}
</script>
