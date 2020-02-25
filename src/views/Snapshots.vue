<template>
  <div>
    <h2 class="is-size-5">The last 10 snapshots</h2>

    <SnapshotDetail v-for="snapshot in snapshots" v-bind:key="snapshot.id" v-bind:data="snapshot" />
  </div>
</template>

<script lang="ts">
import { Component, Vue, Prop } from "vue-property-decorator";
import axios, { AxiosError } from "axios";

import { Snapshot, SnapshotsData, ErrorData } from "@/types";

import SnapshotDetail from "@/components/SnapshotDetail.vue";

@Component({
  components: {
    SnapshotDetail
  }
})
export default class Snapshots extends Vue {
  private snapshots: Snapshot[] = [];

  async load(size = 10) {
    try {
      const response = await axios.get<SnapshotsData>("/api/snapshots/", {
        params: {
          size: size
        }
      });
      const data = response.data;
      this.snapshots = data.snapshots;
    } catch (error) {
      const data = error.response.data as ErrorData;
      alert(data.detail);
    }
  }

  created() {
    this.load();
  }
}
</script>
