<template>
  <SnapshotComponebnt
    v-bind:id="this.$route.params.id"
    v-bind:yaraResult="yaraResult"
  />
</template>

<script lang="ts">
import { Component, Mixins } from "vue-mixin-decorator";
import { Prop } from "vue-property-decorator";

import { ErrorDialogMixin } from "@/components/mixins";
import SnapshotComponebnt from "@/components/snapshots/Snapshot.vue";
import { YaraResult } from "@/types";

@Component({
  components: {
    SnapshotComponebnt,
  },
})
export default class SnapshotView extends Mixins<ErrorDialogMixin>(
  ErrorDialogMixin
) {
  @Prop() private yaraResult!: YaraResult;
}
</script>
