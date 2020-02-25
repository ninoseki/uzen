<template>
  <div>
    <div class="box">
      <b-input class="is-expanded" type="textarea" placeholder="YARA rule" v-model="source"></b-input>
      <br />
      <div class="has-text-centered">
        <b-button type="is-light" @click="scan">Scan</b-button>
      </div>
    </div>
    <h2 v-if="hasCount()">{{ count }} snapshots found</h2>
    <SnapshotDetail v-for="snapshot in snapshots" v-bind:key="snapshot.id" v-bind:data="snapshot" />
  </div>
</template>

<script lang="ts">
import { Component, Prop, Vue } from "vue-property-decorator";
import axios, { AxiosError } from "axios";

import { ErrorData, Snapshot, SnapshotsData } from "@/types";

import SnapshotDetail from "@/components/SnapshotDetail.vue";

@Component({
  components: {
    SnapshotDetail
  }
})
export default class SnapshotForm extends Vue {
  private source: string = "";
  private count: number | undefined = undefined;
  private snapshots: Snapshot[] = [];

  async scan() {
    this.snapshots = [];
    this.count = undefined;

    const loadingComponent = this.$buefy.loading.open({
      container: this.$refs.element
    });

    try {
      const response = await axios.post<SnapshotsData>("/api/yara/scan", {
        source: this.source
      });

      const data = response.data;
      loadingComponent.close();

      this.snapshots = data.snapshots;
      this.count = data.snapshots.length;
    } catch (error) {
      loadingComponent.close();

      const data = error.response.data as ErrorData;
      alert(data.detail);
    }
  }

  hasCount(): boolean {
    return this.count !== undefined;
  }
}
</script>
