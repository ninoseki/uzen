<template>
  <div>
    <div class="box">
      <Form
        ref="form"
        v-bind:name="$route.query.name"
        v-bind:type="$route.query.type"
        v-bind:source="$route.query.source"
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

    <Table v-bind:rules="rules" />

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
import Form from "@/components/rules/Form.vue";
import Table from "@/components/rules/Table.vue";
import { ErrorData, Rule, RuleSearchResults } from "@/types";

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
  private rules: Rule[] = [];

  resetPagination() {
    this.rules = [];
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
      const response = await axios.get<RuleSearchResults>("/api/rules/search", {
        params: params,
      });

      loadingComponent.close();

      this.rules = this.rules.concat(response.data.results);
      this.totalCount = response.data.total;
      this.count = this.rules.length;
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
