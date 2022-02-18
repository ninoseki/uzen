<template>
  <Domain />
</template>

<script lang="ts">
import { useTitle } from "@vueuse/core";
import { defineComponent } from "vue";
import { useRoute } from "vue-router";

import Domain from "@/components/domain/DomainWrapper.vue";

export default defineComponent({
  name: "DomainView",
  components: {
    Domain,
  },
  setup() {
    const route = useRoute();

    const updateTitle = (): void => {
      const hostname = route.params.hostname;
      useTitle(`${hostname} - Uzen`);
    };

    updateTitle();
  },
});
</script>
