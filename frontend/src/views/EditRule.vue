<template>
  <Edit :ruleId="$root.$route.params.id" />
</template>

<script lang="ts">
import { defineComponent } from "@vue/composition-api";

import Edit from "@/components/rules/Edit.vue";

export default defineComponent({
  name: "EditRuleView",
  components: {
    Edit,
  },
});
</script>
