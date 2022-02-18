<template>
  <Edit :ruleId="ruleId" />
</template>

<script lang="ts">
import { defineComponent } from "vue";
import { useRoute } from "vue-router";

import Edit from "@/components/rule/Edit.vue";

export default defineComponent({
  name: "EditRuleView",
  components: {
    Edit,
  },
  setup() {
    const route = useRoute();
    const ruleId = route.params.id as string;

    return { ruleId };
  },
});
</script>
