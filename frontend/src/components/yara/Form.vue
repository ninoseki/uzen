<template>
  <div>
    <div class="box">
      <BasicForm v-bind:source.sync="source" v-bind:target.sync="target" />
      <hr />
      <SnapshotForm ref="form" />
      <br />
      <div class="has-text-centered">
        <b-button
          type="is-light"
          icon-pack="fas"
          icon-left="search"
          @click="scan"
          >Scan</b-button
        >
      </div>
    </div>
    <h2 v-if="hasCount()">{{ count }} snapshots found</h2>

    <SnapshotTable v-bind:snapshots="results" />
  </div>
</template>

<script lang="ts">
import { Component, Mixin, Mixins } from "vue-mixin-decorator";
import { Prop } from "vue-property-decorator";
import axios, { AxiosError } from "axios";

import {
  ErrorData,
  Snapshot,
  TargetTypes,
  SnapshotWithYaraResult,
  CountResponse,
} from "@/types";

import BasicForm from "@/components/yara/BasicForm.vue";
import SnapshotForm from "@/components/snapshots/SearchForm.vue";
import SnapshotTable from "@/components/snapshots/Table.vue";

import { ErrorDialogMixin } from "@/components/mixins";

@Component({
  components: {
    BasicForm,
    SnapshotForm,
    SnapshotTable,
  },
})
export default class YaraForm extends Mixins<ErrorDialogMixin>(
  ErrorDialogMixin
) {
  private source: string = "";
  private target: TargetTypes = "body";
  private count: number | undefined = undefined;
  private results: SnapshotWithYaraResult[] = [];

  async scan() {
    this.results = [];
    this.count = undefined;

    const loadingComponent = this.$buefy.loading.open({
      container: this.$el.firstElementChild,
    });

    const params = (this.$refs.form as SnapshotForm).filtersParams();
    // get total count of snapshots and set it as a size
    const totalCount = await this.getTotalCount();
    if (totalCount !== undefined) {
      params["size"] = totalCount;
    }

    try {
      const response = await axios.post<SnapshotWithYaraResult[]>(
        "/api/yara/scan",
        {
          source: this.source,
          target: this.target,
        },
        { params: params }
      );

      loadingComponent.close();

      this.results = response.data;
      this.count = this.results.length;
    } catch (error) {
      loadingComponent.close();

      const data = error.response.data as ErrorData;
      this.alertError(data);
    }
  }

  hasCount(): boolean {
    return this.count !== undefined;
  }

  async getTotalCount(): Promise<number | undefined> {
    try {
      const response = await axios.get<CountResponse>("/api/snapshots/count");
      return response.data.count;
    } catch (error) {
      return undefined;
    }
  }
}
</script>
