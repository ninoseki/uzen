<template>
  <div>
    <div class="box">
      <SnapshotSearch
        ref="search"
        v-bind:sha256="$route.query.sha256"
        v-bind:asn="$route.query.asn"
        v-bind:contentType="$route.query.contentType"
        v-bind:hostname="$route.query.hostname"
        v-bind:ipAddress="$route.query.ipAddress"
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
import { Component, Mixin, Mixins } from "vue-mixin-decorator";
import { Prop } from "vue-property-decorator";
import axios, { AxiosError } from "axios";

import { Snapshot, ErrorData, SnapshotSearchResults } from "@/types";

import SnapshotSearch from "@/components/snapshots/Search.vue";
import SnapshotTable from "@/components/snapshots/Table.vue";

import {
  SearchFormMixin,
  ErrorDialogMixin,
  SearchFormComponentMixin,
} from "@/components/mixins";

@Component({
  components: {
    SnapshotSearch,
    SnapshotTable,
  },
})
export default class Snapshots extends Mixins<SearchFormComponentMixin>(
  ErrorDialogMixin,
  SearchFormMixin
) {
  private snapshots: Snapshot[] = [];

  resetPagination() {
    this.snapshots = [];
    this.size = this.DEFAULT_PAGE_SIZE;
    this.offset = this.DEFAULT_OFFSET;
  }

  async search(additonalLoading = false) {
    const loadingComponent = this.$buefy.loading.open({
      container: this.$refs.element,
    });

    if (!additonalLoading) {
      this.resetPagination();
    }

    const params = (this.$refs.search as SnapshotSearch).filtersParams();
    params["size"] = this.size;
    params["offset"] = this.offset;

    try {
      const response = await axios.get<SnapshotSearchResults>(
        "/api/snapshots/search",
        {
          params: params,
        }
      );

      loadingComponent.close();

      this.snapshots = this.snapshots.concat(response.data.results);
      this.totalCount = response.data.total;
      this.count = this.snapshots.length;
    } catch (error) {
      loadingComponent.close();

      const data = error.response.data as ErrorData;
      this.alertError(data);
    }
  }

  loadMore() {
    this.offset += this.size;
    this.search(true);
  }

  initSearch() {
    this.search();
  }

  mounted() {
    if (Object.keys(this.$route.query).length > 0) {
      this.initSearch();
    }
  }
}
</script>
