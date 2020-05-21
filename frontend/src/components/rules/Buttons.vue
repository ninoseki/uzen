<template>
  <div>
    <div v-if="hasRules()" class="buttons">
      <b-button
        v-for="rule in uniqueRules()"
        v-bind:key="rule.id"
        tag="router-link"
        :to="{ name: 'Rule', params: { id: rule.id } }"
        type="is-info"
      >
        {{ rule.name }}
      </b-button>
    </div>
    <div v-else>
      N/A
    </div>
  </div>
</template>

<script lang="ts">
import { Component, Prop, Vue } from "vue-property-decorator";

import { Rule } from "@/types";

@Component
export default class Buttons extends Vue {
  @Prop() private rules!: Rule[];

  uniqueRules(): Rule[] {
    let rules: Rule[] = [];
    const memo = new Set();
    for (const rule of this.rules) {
      if (!memo.has(rule.id)) {
        rules = rules.concat(rule);
      }
      memo.add(rule.id);
    }
    return rules;
  }

  hasRules(): boolean {
    return this.rules.length > 0;
  }
}
</script>
