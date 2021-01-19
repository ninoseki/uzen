<template>
  <div>
    <div class="table-container" v-if="hasClassifications">
      <b-table :data="classifications">
        <b-table-column field="name" label="Name" v-slot="props">
          {{ props.row.name }}
        </b-table-column>

        <b-table-column field="malicious" label="Malicious" v-slot="props">
          {{ props.row.malicious }}
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
import { Classification } from "@/types";

export default defineComponent({
  name: "Classifications",
  props: {
    classifications: {
      type: Array as PropType<Classification[]>,
      required: true,
    },
  },
  components: { NA },
  setup(props) {
    const hasClassifications = computed((): boolean => {
      return props.classifications.length > 0;
    });

    return { hasClassifications };
  },
});
</script>
