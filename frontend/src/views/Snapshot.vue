<template>
  <SnapshotComponebnt
    v-bind:snapshot="snapshot"
    v-bind:yaraResult="yaraResult"
    v-if="hasSnapshot()"
  />
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
  @Prop() private test!: string;
  private snapshot: Snapshot | undefined = undefined;

  async load() {
    const loadingComponent = this.$buefy.loading.open({
      container: this.$refs.element,
    });

    try {
      const id = this.$route.params.id;
      const response = await axios.get<Snapshot>(`/api/snapshots/${id}`);
      this.snapshot = response.data;

      loadingComponent.close();
      this.$forceUpdate();
    } catch (error) {
      loadingComponent.close();

      const data = error.response.data as ErrorData;
      this.alertError(data);
    }
  }

  created() {
    this.load();
  }

  hasSnapshot(): boolean {
    return this.snapshot !== undefined;
  }
}
</script>
