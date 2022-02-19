<template>
  <Form />
</template>

<script lang="ts">
import { defineComponent } from "vue";

import Form from "@/components/bulk/Form.vue";

export default defineComponent({
  name: "BulkItem",
  components: {
    Form,
  },
});
</script>
