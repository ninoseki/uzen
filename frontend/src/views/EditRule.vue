<template>
  <Edit v-bind:id="this.$route.params.id" />
</template>

<script lang="ts">
import { Component, Mixins } from "vue-mixin-decorator";

import { ErrorDialogMixin } from "@/components/mixins";
import Edit from "@/components/rules/Edit.vue";

@Component({
  components: {
    Edit,
  },
})
export default class RuleEditView extends Mixins<ErrorDialogMixin>(
  ErrorDialogMixin
) {}
</script>
