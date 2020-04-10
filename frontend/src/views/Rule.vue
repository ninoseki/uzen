<template>
  <RuleComponebnt v-bind:rule="rule" v-if="hasRule()" />
</template>

<script lang="ts">
import { Component, Mixin, Mixins } from "vue-mixin-decorator";
import { Prop } from "vue-property-decorator";
import axios, { AxiosError } from "axios";

import { Rule, ErrorData } from "@/types";

import RuleComponebnt from "@/components/rules/Rule.vue";

import { ErrorDialogMixin } from "@/components/mixins";

@Component({
  components: {
    RuleComponebnt,
  },
})
export default class RuleView extends Mixins<ErrorDialogMixin>(
  ErrorDialogMixin
) {
  private rule: Rule | undefined = undefined;

  async load() {
    try {
      const id = this.$route.params.id;
      const response = await axios.get<Rule>(`/api/rules/${id}`);
      this.rule = response.data;

      this.$forceUpdate();
    } catch (error) {
      const data = error.response.data as ErrorData;
      this.alertError(data);
    }
  }

  created() {
    this.load();
  }

  hasRule(): boolean {
    return this.rule !== undefined;
  }
}
</script>
