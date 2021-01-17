<template>
  <Rule :ruleId="$route.params.id" />
</template>

<script lang="ts">
import { defineComponent } from "@vue/composition-api";

import Rule from "@/components/rules/Rule.vue";

export default defineComponent({
  name: "RuleView",
  components: {
    Rule,
  },
});
</script>
