<template>
  <div>
    <pre v-if="hasCertificate">{{ certificate }}</pre>
    <NA v-else />
  </div>
</template>

<script lang="ts">
import { computed, defineComponent } from "@vue/composition-api";

import NA from "@/components/ui/NA.vue";

export default defineComponent({
  name: "Certificate",
  components: { NA },
  props: {
    certificate: {
      type: String,
      required: false,
    },
  },
  setup(props) {
    const hasCertificate = computed((): boolean => {
      return props.certificate !== null;
    });

    return { hasCertificate };
  },
});
</script>
