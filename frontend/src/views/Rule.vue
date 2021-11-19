<template>
  <Rule :ruleId="ruleId" />
</template>

<script lang="ts">
import { defineComponent } from "vue";
import { useRoute } from "vue-router";

import Rule from "@/components/rule/RuleWrapper.vue";

export default defineComponent({
  name: "RuleView",
  components: {
    Rule,
  },
  setup() {
    const route = useRoute();
    const ruleId = route.params.id as string;

    return { ruleId };
  },
});
</script>
