<template>
  <div>
    <pre v-if="hasWhois">{{ whois }}</pre>
    <NA v-else />
  </div>
</template>

<script lang="ts">
import { computed, defineComponent } from "@vue/composition-api";

import NA from "@/components/ui/NA.vue";

export default defineComponent({
  name: "Whois",
  props: {
    whois: {
      type: String,
      required: false,
    },
  },
  components: {
    NA,
  },
  setup(props) {
    const hasWhois = computed((): boolean => {
      return props.whois !== null;
    });
    return { hasWhois };
  },
});
</script>
