<template>
  <SnapshotForm />
</template>

<script lang="ts">
import { defineComponent } from "@vue/composition-api";

import SnapshotForm from "@/components/snapshots/Form.vue";

export default defineComponent({
  name: "HomeView",
  components: {
    SnapshotForm,
  },
});
</script>
