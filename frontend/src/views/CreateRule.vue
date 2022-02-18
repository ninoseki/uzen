<template>
  <Register />
</template>

<script lang="ts">
import { defineComponent } from "vue";

import Register from "@/components/rule/Create.vue";

export default defineComponent({
  name: "RulesView",
  components: {
    Register,
  },
});
</script>
