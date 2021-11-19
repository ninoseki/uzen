<template>
  <div>
    <div v-if="rules.length > 0" class="buttons">
      <button class="button is-info" v-for="rule in uniqueRules" :key="rule.id">
        <router-link :to="{ name: 'Rule', params: { id: rule.id } }">
          {{ rule.name }}
        </router-link>
      </button>
    </div>
    <div v-else>N/A</div>
  </div>
</template>

<script lang="ts">
import { computed, defineComponent, PropType } from "vue";

import { Rule } from "@/types";

export default defineComponent({
  name: "RuleButtons",
  props: {
    rules: {
      type: Array as PropType<Rule[]>,
      required: true,
    },
  },
  setup(props) {
    const uniqueRules = computed((): Rule[] => {
      let rules: Rule[] = [];
      const memo = new Set();
      for (const rule of props.rules) {
        if (!memo.has(rule.id)) {
          rules = rules.concat(rule);
        }
        memo.add(rule.id);
      }
      return rules;
    });

    return { uniqueRules };
  },
});
</script>
