<template>
  <RuleComponebnt v-bind:id="id" />
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
  private id: string | undefined = undefined;

  created() {
    this.id = this.$route.params.id;
  }
}
</script>
