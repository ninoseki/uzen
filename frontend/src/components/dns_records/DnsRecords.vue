<template>
  <div>
    <div class="table-container" v-if="hasDnsRecords">
      <b-table :data="dnsRecords">
        <b-table-column field="type" label="Type" v-slot="props">
          {{ props.row.type }}
        </b-table-column>

        <b-table-column field="value" label="Value" v-slot="props">
          {{ props.row.value }}
        </b-table-column>
      </b-table>
    </div>
    <div v-else>
      <NA />
    </div>
  </div>
</template>

<script lang="ts">
import { computed, defineComponent, PropType } from "@vue/composition-api";

import NA from "@/components/ui/NA.vue";
import { DnsRecord } from "@/types";

export default defineComponent({
  name: "DnsRecords",
  props: {
    dnsRecords: {
      type: Array as PropType<DnsRecord[]>,
      required: true,
    },
  },
  components: { NA },
  setup(props) {
    const hasDnsRecords = computed((): boolean => {
      return props.dnsRecords.length > 0;
    });

    return { hasDnsRecords };
  },
});
</script>
