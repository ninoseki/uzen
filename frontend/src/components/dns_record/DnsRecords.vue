<template>
  <div>
    <div class="table-container" v-if="hasDnsRecords">
      <table class="table is-completely-borderless is-fullwidth">
        <thead>
          <tr>
            <th>Type</th>
            <th>Value</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="(record, index) in dnsRecords" :key="index">
            <td>{{ record.type }}</td>
            <td>{{ record.value }}</td>
          </tr>
        </tbody>
      </table>
    </div>
    <div v-else>
      <NA />
    </div>
  </div>
</template>

<script lang="ts">
import { computed, defineComponent, PropType } from "vue";

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
