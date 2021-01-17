<template>
  <Form />
</template>

<script lang="ts">
import { defineComponent } from "@vue/composition-api";

import Form from "@/components/bulk/Form.vue";

export default defineComponent({
  name: "Bulk",
  components: {
    Form,
  },
});
</script>
