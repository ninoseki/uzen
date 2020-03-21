<template>
  <div>
    <div class="box">
      <SnapshotSearch
        ref="search"
        v-bind:sha256="$route.query.sha256"
        v-bind:asn="$route.query.asn"
        v-bind:content_type="$route.query.content_type"
        v-bind:hostname="$route.query.hostname"
        v-bind:ip_address="$route.query.ip_address"
        v-bind:server="$route.query.server"
      />
      <br />

      <div class="has-text-centered">
        <b-button type="is-light" @click="initSearch()">Search</b-button>
      </div>
    </div>

    <h2 v-if="hasCount()">Search results ({{ count }} / {{ totalCount }})</h2>

    <SnapshotTable v-bind:snapshots="snapshots" />

    <b-button v-if="hasLoadMore()" type="is-dark" @click="loadMore"
      >Load more...</b-button
    >
  </div>
</template>

<script lang="ts">
import { Component, Vue, Prop } from "vue-property-decorator";
import axios, { AxiosError } from "axios";

import { SnapshotCount, Snapshot, ErrorData } from "@/types";

import Counter from "@/components/ui/Counter.vue";
import SnapshotSearch from "@/components/snapshots/Search.vue";
import SnapshotTable from "@/components/snapshots/Table.vue";

@Component({
  components: {
    Counter,
    SnapshotSearch,
    SnapshotTable
  }
})
export default class Snapshots extends Vue {
  DEFAULT_PAGE_SIZE = 10;
  DEFAULT_OFFSET = 0;

  private snapshots: Snapshot[] = [];
  private count: number | undefined = undefined;
  private totalCount: number = 0;
  private size = this.DEFAULT_PAGE_SIZE;
  private offset = this.DEFAULT_OFFSET;

  resetPagination() {
    this.snapshots = [];
    this.size = this.DEFAULT_PAGE_SIZE;
    this.offset = this.DEFAULT_OFFSET;
  }

  async search(additonalLoading = false) {
    const loadingComponent = this.$buefy.loading.open({
      container: this.$refs.element
    });

    if (!additonalLoading) {
      this.resetPagination();
    }

    const params = (this.$refs.search as SnapshotSearch).filtersParams();
    params["size"] = this.size;
    params["offset"] = this.offset;

    try {
      const response = await axios.get<Snapshot[]>("/api/snapshots/search", {
        params: params
      });

      loadingComponent.close();

      this.snapshots = this.snapshots.concat(response.data);
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

  async getTotalCount() {
    try {
      const params = (this.$refs.search as SnapshotSearch).filtersParams();

      const response = await axios.get<SnapshotCount>("/api/snapshots/count", {
        params: params
      });
      const data = response.data;
      this.totalCount = data.count;
      this.$forceUpdate();
    } catch (error) {
      this.totalCount = 0;
    }
  }

  hasLoadMore() {
    const count = this.count || 0;
    const total = this.totalCount || 0;

    return count < total;
  }

  loadMore() {
    this.offset += this.size;
    this.search(true);
  }

  initSearch() {
    this.search();
    this.getTotalCount();
  }

  mounted() {
    if (Object.keys(this.$route.query).length > 0) {
      this.initSearch();
    }
  }
}
</script>
