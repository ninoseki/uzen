<template>
  <SnapshotDetail v-bind:snapshot="snapshot" v-if="hasSnapshot()" />
</template>

<script lang="ts">
import { Component, Vue, Prop } from "vue-property-decorator";
import axios, { AxiosError } from "axios";

import { Snapshot, ErrorData } from "@/types";

import SnapshotDetail from "@/components/SnapshotDetail.vue";

@Component({
  components: {
    SnapshotDetail
  }
})
export default class SnapshotView extends Vue {
  private snapshot: Snapshot | undefined = undefined;

  async load() {
    try {
      const id = this.$route.params.id;
      const response = await axios.get<Snapshot>(`/api/snapshots/${id}`);
      this.snapshot = response.data;

      this.$forceUpdate();
    } catch (error) {
      const data = error.response.data as ErrorData;
      alert(data.detail);
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
