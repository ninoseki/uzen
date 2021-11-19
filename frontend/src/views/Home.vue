<template>
  <SnapshotForm />
</template>

<script lang="ts">
import { defineComponent } from "vue";

import SnapshotForm from "@/components/snapshot/Form.vue";

export default defineComponent({
  name: "HomeView",
  components: {
    SnapshotForm,
  },
});
</script>
