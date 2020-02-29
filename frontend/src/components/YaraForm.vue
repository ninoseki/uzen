<template>
  <div>
    <div class="box">
      <b-field label="YARA rule">
        <b-input
          class="is-expanded"
          type="textarea"
          placeholder="rule foo: bar {strings: $a = 'lmn' condition: $a}"
          v-model="source"
        ></b-input>
      </b-field>

      <SnapshotSearch ref="search" />

      <br />
      <div class="has-text-centered">
        <b-button type="is-light" @click="scan">Scan</b-button>
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
import { Component, Prop, Vue } from "vue-property-decorator";
import axios, { AxiosError } from "axios";

import { ErrorData, Snapshot, SnapshotsData, SearchFilters } from "@/types";

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
export default class YaraForm extends Vue {
  private source: string = "";
  private count: number | undefined = undefined;
  private snapshots: Snapshot[] = [];

  async scan() {
    this.snapshots = [];
    this.count = undefined;

    const loadingComponent = this.$buefy.loading.open({
      container: this.$refs.element
    });

    const params = (this.$refs.search as SnapshotSearch).filtersParams();

    try {
      const response = await axios.post<SnapshotsData>(
        "/api/yara/scan",
        {
          source: this.source
        },
        { params: params }
      );

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
