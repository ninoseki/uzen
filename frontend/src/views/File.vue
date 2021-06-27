<template>
  <File />
</template>

<script lang="ts">
import { defineComponent } from "@vue/composition-api";
import { useTitle } from "@vueuse/core";

import File from "@/components/file/FileWrapper.vue";

export default defineComponent({
  name: "FileView",
  components: {
    File,
  },
  setup(_, { root }) {
    const updateTitle = (): void => {
      const hash = root.$route.params.hash;
      useTitle(`${hash} - Uzen`);
    };

    updateTitle();
  },
});
</script>
