<template>
  <YaraForm />
</template>

<script lang="ts">
import { defineComponent } from "vue";

import YaraForm from "@/components/yara/Form.vue";

export default defineComponent({
  name: "YaraFormView",
  components: {
    YaraForm,
  },
});
</script>
