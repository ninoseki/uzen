<template>
  <div>
    <div class="box">
      <BasicYaraForm v-bind:source.sync="source" v-bind:target.sync="target" />
      <hr>
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
    <SnapshotDetail
      v-for="snapshot in snapshots"
      v-bind:key="snapshot.id"
      v-bind:data="snapshot"
    />
  </div>
</template>

<script lang="ts">
import { Component, Prop, Vue } from "vue-property-decorator";
import axios, { AxiosError } from "axios";

import {
  ErrorData,
  Snapshot,
  SearchFilters,
  TargetTypes
} from "@/types";

import Counter from "@/components/Counter.vue";
import SnapshotDetail from "@/components/SnapshotDetail.vue";
import SnapshotSearch from "@/components/SnapshotSearch.vue";
import BasicYaraForm from "@/components/BasicYaraForm.vue";

@Component({
  components: {
    BasicYaraForm,
    Counter,
    SnapshotDetail,
    SnapshotSearch
  }
})
export default class YaraForm extends Vue {
  private source: string = "";
  private target: TargetTypes = "body";
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
      const response = await axios.post<Snapshot[]>(
        "/api/yara/scan",
        {
          source: this.source,
          target: this.target
        },
        { params: params }
      );

      loadingComponent.close();

      this.snapshots = response.data;
      this.count = this.snapshots.length;
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
