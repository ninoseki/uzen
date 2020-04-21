<template>
  <div>
    <div class="box">
      <Form ref="form" />

      <br />

      <div class="has-text-centered">
        <b-button type="is-light" @click="initSearch()">Search</b-button>
      </div>
    </div>

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

import { Match, ErrorData, MatchSearchResults } from "@/types";

import Table from "@/components/matches/Table.vue";
import Form from "@/components/matches/Form.vue";

import {
  SearchFormMixin,
  ErrorDialogMixin,
  SearchFormComponentMixin,
} from "@/components/mixins";

@Component({
  components: {
    Form,
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

    const params = (this.$refs.form as Form).filtersParams();
    params["size"] = this.size;
    params["offset"] = this.offset;

    try {
      const response = await axios.get<MatchSearchResults>(
        "/api/matches/search",
        {
          params: params,
        }
      );

      loadingComponent.close();

      this.matches = this.matches.concat(response.data.results);
      this.totalCount = response.data.total;
      this.count = this.matches.length;
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
}
</script>
