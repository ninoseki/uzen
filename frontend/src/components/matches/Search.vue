<template>
  <div>
    <div class="box">
      <Form ref="form" v-bind:ruleId="ruleId" v-bind:snapshotId="snapshotId" />

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

    <Table v-bind:matches="matches" />

    <b-button v-if="hasLoadMore()" type="is-dark" @click="loadMore"
      >Load more...</b-button
    >
  </div>
</template>

<script lang="ts">
import axios from "axios";
import { Component, Mixins } from "vue-mixin-decorator";
import { Prop } from "vue-property-decorator";

import Form from "@/components/matches/Form.vue";
import Table from "@/components/matches/Table.vue";
import {
  ErrorDialogMixin,
  SearchFormComponentMixin,
  SearchFormMixin,
} from "@/components/mixins";
import { ErrorData, Match, MatchSearchResults } from "@/types";

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

  @Prop() private ruleId: string | undefined;
  @Prop() private snapshotId: string | undefined;

  resetPagination() {
    this.matches = [];
    this.size = this.DEFAULT_PAGE_SIZE;
    this.oldestCreatedAt = this.nowDatetime();
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
    params["toAt"] = this.minDatetime(params["toAt"], this.oldestCreatedAt);

    try {
      const response = await axios.get<MatchSearchResults>(
        "/api/matches/search",
        {
          params: params,
        }
      );

      loadingComponent.close();

      this.matches = this.matches.concat(response.data.results);
      this.count = this.matches.length;
      this.oldestCreatedAt = this.matches[this.count - 1].createdAt;
      if (!additonalLoading) {
        this.totalCount = response.data.total;
      }
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
