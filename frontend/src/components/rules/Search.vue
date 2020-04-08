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
        <b-button type="is-light" @click="initSearch()">Search</b-button>
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
import { Component, Vue, Prop } from "vue-property-decorator";
import axios, { AxiosError } from "axios";

import { Rule, RuleFilters, Count, ErrorData } from "@/types";

import Counter from "@/components/ui/Counter.vue";
import Form from "@/components/rules/Form.vue";
import Table from "@/components/rules/Table.vue";

@Component({
  components: {
    Counter,
    Form,
    Table,
  },
})
export default class Search extends Vue {
  DEFAULT_PAGE_SIZE = 10;
  DEFAULT_OFFSET = 0;

  private rules: Rule[] = [];
  private count: number | undefined = undefined;
  private totalCount: number = 0;
  private size = this.DEFAULT_PAGE_SIZE;
  private offset = this.DEFAULT_OFFSET;

  resetPagination() {
    this.rules = [];
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
      const response = await axios.get<Rule[]>("/api/rules/search", {
        params: params,
      });

      loadingComponent.close();

      this.rules = this.rules.concat(response.data);
      this.count = this.rules.length;
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
      const params = (this.$refs.form as Form).filtersParams();

      const response = await axios.get<Count>("/api/rules/count", {
        params: params,
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
