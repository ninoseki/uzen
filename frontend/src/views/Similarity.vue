<template>
  <Form />
</template>

<script lang="ts">
import { defineComponent } from "@vue/composition-api";

import Form from "@/components/similarity/Form.vue";

export default defineComponent({
  name: "SimilarityView",
  components: {
    Form,
  },
});
</script>
