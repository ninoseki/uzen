<template>
  <div>
    <div class="table-container" v-if="hasDnsRecords">
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
    <div v-else>
      <NA />
    </div>
  </div>
</template>

<script lang="ts">
import { Component, Prop, Vue } from "vue-property-decorator";

import NA from "@/components/ui/NA.vue";
import { DnsRecord } from "@/types";

@Component({
  components: {
    NA,
  },
})
export default class DnsRecords extends Vue {
  @Prop() private dnsRecords!: DnsRecord[];

  get hasDnsRecords(): boolean {
    return this.dnsRecords.length > 0;
  }
}
</script>
