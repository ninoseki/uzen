<template>
  <SnapshotComponebnt
    v-bind:id="this.$route.params.id"
    v-bind:yaraResult="yaraResult"
  />
</template>

<script lang="ts">
import axios, { AxiosError } from "axios";
import { Component, Mixin, Mixins } from "vue-mixin-decorator";
import { Prop } from "vue-property-decorator";

import { ErrorDialogMixin } from "@/components/mixins";
import SnapshotComponebnt from "@/components/snapshots/Snapshot.vue";
import { ErrorData, Snapshot, YaraResult } from "@/types";

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
