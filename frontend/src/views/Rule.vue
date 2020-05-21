<template>
  <RuleComponebnt v-bind:id="this.$route.params.id" />
</template>

<script lang="ts">
import { Component, Mixins } from "vue-mixin-decorator";

import { ErrorDialogMixin } from "@/components/mixins";
import RuleComponebnt from "@/components/rules/Rule.vue";

@Component({
  components: {
    RuleComponebnt,
  },
})
export default class RuleView extends Mixins<ErrorDialogMixin>(
  ErrorDialogMixin
) {}
</script>
