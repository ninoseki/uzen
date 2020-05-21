<template>
  <RuleComponebnt v-bind:id="id" />
</template>

<script lang="ts">
import axios, { AxiosError } from "axios";
import { Component, Mixin, Mixins } from "vue-mixin-decorator";
import { Prop } from "vue-property-decorator";

import { ErrorDialogMixin } from "@/components/mixins";
import RuleComponebnt from "@/components/rules/Rule.vue";
import { ErrorData, Rule } from "@/types";

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
