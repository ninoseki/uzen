<template>
  <div class="table-container">
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
  </div>
</template>

<script lang="ts">
import { Component, Prop, Vue } from "vue-property-decorator";

import { DnsRecord } from "@/types";

@Component
export default class DnsRecords extends Vue {
  @Prop() private dnsRecords!: DnsRecord[];
}
</script>
