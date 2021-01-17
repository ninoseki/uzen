<template>
  <Domain />
</template>

<script lang="ts">
import { defineComponent } from "@vue/composition-api";

import Domain from "@/components/domain/Domain.vue";

export default defineComponent({
  name: "DomainView",
  components: {
    Domain,
  },

  setup(_, { root }) {
    const updateTitle = (): void => {
      const hostname = root.$route.params.hostname;
      document.title = `${hostname} - Uzen`;
    };

    updateTitle();
  },
});
</script>
