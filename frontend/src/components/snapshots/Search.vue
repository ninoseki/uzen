<template>
  <div>
    <div class="box">
      <Form
        ref="form"
        v-bind:sha256="$route.query.sha256"
        v-bind:asn="$route.query.asn"
        v-bind:contentType="$route.query.contentType"
        v-bind:hostname="$route.query.hostname"
        v-bind:ipAddress="$route.query.ipAddress"
        v-bind:server="$route.query.server"
      />

      <br />

      <div class="has-text-centered">
        <b-button
          type="is-light"
          icon-pack="fas"
          icon-left="search"
          @click="initSearch()"
          >Search</b-button
        >
      </div>
    </div>

    <h2 v-if="hasCount()">Search results ({{ count }} / {{ totalCount }})</h2>

    <Table v-bind:snapshots="snapshots" />

    <b-button v-if="hasLoadMore()" type="is-dark" @click="loadMore"
      >Load more...</b-button
    >
  </div>
</template>

<script lang="ts">
import axios from "axios";
import { Component, Mixins } from "vue-mixin-decorator";

import {
  ErrorDialogMixin,
  SearchFormComponentMixin,
  SearchFormMixin,
} from "@/components/mixins";
import Form from "@/components/snapshots/SearchForm.vue";
import Table from "@/components/snapshots/Table.vue";
import { ErrorData, Snapshot, SnapshotSearchResults } from "@/types";

@Component({
  components: {
    Form,
    Table,
  },
})
export default class SearchForm extends Mixins<SearchFormComponentMixin>(
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
      container: this.$el.firstElementChild,
    });

    if (!additonalLoading) {
      this.resetPagination();
    }

    const params = (this.$refs.form as Form).filtersParams();
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
