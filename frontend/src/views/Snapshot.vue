<template>
  <SnapshotComponebnt v-bind:id="id" v-bind:yaraResult="yaraResult" />
</template>

<script lang="ts">
import { Component, Mixin, Mixins } from "vue-mixin-decorator";
import { Prop } from "vue-property-decorator";
import axios, { AxiosError } from "axios";

import { Snapshot, ErrorData, YaraResult } from "@/types";

import SnapshotComponebnt from "@/components/snapshots/Snapshot.vue";

import { ErrorDialogMixin } from "@/components/mixins";

@Component({
  components: {
    SnapshotComponebnt,
  },
})
export default class SnapshotView extends Mixins<ErrorDialogMixin>(
  ErrorDialogMixin
) {
  @Prop() private yaraResult!: YaraResult;

  private id: string | undefined = undefined;

  created() {
    this.id = this.$route.params.id;
  }
}
</script>
