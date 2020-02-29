<template>
  <div>
    <div class="box">
      <SnapshotSearch ref="search" />
      <br />

      <div class="has-text-centered">
        <b-button type="is-light" @click="search">Search</b-button>
      </div>
    </div>

    <h2 v-if="hasCount()">
      {{ count }} snapshots found
      <Counter />
    </h2>

    <SnapshotDetail v-for="snapshot in snapshots" v-bind:key="snapshot.id" v-bind:data="snapshot" />
  </div>
</template>

<script lang="ts">
import { Component, Vue, Prop } from "vue-property-decorator";
import axios, { AxiosError } from "axios";

import { Snapshot, SnapshotsData, ErrorData } from "@/types";

import Counter from "@/components/Counter.vue";
import SnapshotDetail from "@/components/SnapshotDetail.vue";
import SnapshotSearch from "@/components/SnapshotSearch.vue";

@Component({
  components: {
    Counter,
    SnapshotDetail,
    SnapshotSearch
  }
})
export default class Snapshots extends Vue {
  private snapshots: Snapshot[] = [];
  private count: number | undefined = undefined;

  async search(size = 10) {
    const params = (this.$refs.search as SnapshotSearch).filtersParams();

    try {
      const response = await axios.get<SnapshotsData>("/api/snapshots/search", {
        params: params
      });
      const data = response.data;
      this.snapshots = data.snapshots;
      this.count = data.snapshots.length;
    } catch (error) {
      const data = error.response.data as ErrorData;
      alert(data.detail);
    }
  }

  hasCount(): boolean {
    return this.count !== undefined;
  }

  mounted() {
    this.search();
  }
}
</script>
