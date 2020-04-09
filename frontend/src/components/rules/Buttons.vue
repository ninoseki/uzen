<template>
  <div>
    <div v-if="hasRules()" class="buttons">
      <b-button
        v-for="rule in rules"
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
import { Component, Vue, Prop } from "vue-property-decorator";

import { Rule } from "@/types";

@Component
export default class Buttons extends Vue {
  @Prop() private rules!: Rule[];

  hasRules(): boolean {
    return this.rules.length > 0;
  }
}
</script>
