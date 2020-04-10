<template>
  <div>
    <h2 v-if="hasCount()">Search results ({{ count }} / {{ totalCount }})</h2>

    <Table v-bind:matches="matches" />

    <b-button v-if="hasLoadMore()" type="is-dark" @click="loadMore"
      >Load more...</b-button
    >
  </div>
</template>

<script lang="ts">
import { Component, Mixin, Mixins } from "vue-mixin-decorator";
import { Prop } from "vue-property-decorator";
import axios, { AxiosError } from "axios";

import { Match, Count, ErrorData } from "@/types";

import Counter from "@/components/ui/Counter.vue";
import Table from "@/components/matches/Table.vue";

import {
  SearchFormMixin,
  ErrorDialogMixin,
  SearchFormComponentMixin,
} from "@/components/mixins";

@Component({
  components: {
    Counter,
    Table,
  },
})
export default class Search extends Mixins<SearchFormComponentMixin>(
  ErrorDialogMixin,
  SearchFormMixin
) {
  private matches: Match[] = [];

  resetPagination() {
    this.matches = [];
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

    const params = {
      size: this.size,
      offset: this.offset,
    };

    try {
      const response = await axios.get<Match[]>("/api/matches/search", {
        params: params,
      });

      loadingComponent.close();

      this.matches = this.matches.concat(response.data);
      this.count = this.matches.length;
    } catch (error) {
      loadingComponent.close();

      const data = error.response.data as ErrorData;
      this.alertError(data);
    }
  }

  async getTotalCount() {
    try {
      const response = await axios.get<Count>("/api/matches/count");
      const data = response.data;
      this.totalCount = data.count;
      this.$forceUpdate();
    } catch (error) {
      this.totalCount = 0;
    }
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
    this.initSearch();
  }
}
</script>
