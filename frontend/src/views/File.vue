<template>
  <File />
</template>

<script lang="ts">
import { useTitle } from "@vueuse/core";
import { defineComponent } from "vue";
import { useRoute } from "vue-router";

import File from "@/components/file/FileWrapper.vue";

export default defineComponent({
  name: "FileView",
  components: {
    File,
  },
  setup() {
    const route = useRoute();

    const updateTitle = (): void => {
      const hash = route.params.hash;
      useTitle(`${hash} - Uzen`);
    };

    updateTitle();
  },
});
</script>
