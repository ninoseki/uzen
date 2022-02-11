<template>
  <div class="box">
    <Form ref="form" :ruleId="ruleId" :snapshotId="snapshotId" />

    <div class="has-text-centered mt-5">
      <button class="button is-light" @click="initSearch">
        <span class="icon">
          <i class="fas fa-search"></i>
        </span>
        <span>Search</span>
      </button>
    </div>
  </div>

  <Loading v-if="searchTask.isRunning"></Loading>
  <Error
    :error="searchTask.last?.error.response.data"
    v-else-if="searchTask.isError"
  ></Error>

  <h2 v-if="count !== undefined">
    Search results ({{ count }} / {{ totalCount }})
  </h2>

  <MatchesTable v-bind:matches="matches" />

  <button
    class="button is-dark"
    v-if="hasLoadMore(count, totalCount)"
    @click="loadMore"
  >
    Load more...
  </button>
</template>

<script lang="ts">
import { defineComponent, onMounted, ref } from "vue";
import { useRoute } from "vue-router";

import Form from "@/components/match/Form.vue";
import MatchesTable from "@/components/match/Table.vue";
import Error from "@/components/ui/SimpleError.vue";
import Loading from "@/components/ui/SimpleLoading.vue";
import { Match } from "@/types";
import { DEFAULT_PAGE_SIZE, hasLoadMore } from "@/utils/form";
import { generateSearchMatchesTask } from "@/api-helper";

export default defineComponent({
  name: "MatchesSearch",
  props: {
    ruleId: String,
    snapshotId: String,
  },
  components: {
    Error,
    Form,
    Loading,
    MatchesTable,
  },
  setup() {
    const route = useRoute();

    const matches = ref<Match[]>([]);
    const count = ref<number | undefined>(undefined);
    const totalCount = ref(0);
    const searchBefore = ref<string | undefined>(undefined);

    const size = DEFAULT_PAGE_SIZE;

    const form = ref<InstanceType<typeof Form>>();

    const resetPagination = () => {
      matches.value = [];
      count.value = undefined;
      searchBefore.value = undefined;
    };

    const searchTask = generateSearchMatchesTask();

    const search = async () => {
      const params = form.value?.filtersParams() || {};
      params["size"] = size;

      if (searchBefore.value) {
        params["searchBefore"] = searchBefore.value;
      }

      return await searchTask.perform(params);
    };

    const searchWithAdditionalLoading = async (additionalLoading = false) => {
      if (!additionalLoading) {
        resetPagination();
      }

      const res = await search();

      matches.value = matches.value.concat(res.results);
      count.value = matches.value.length;

      if (count.value > 0) {
        searchBefore.value = matches.value[count.value - 1].id;
      }

      if (!additionalLoading) {
        totalCount.value = res.total;
      }

      return;
    };

    const loadMore = async () => {
      await searchWithAdditionalLoading(true);
    };

    const initSearch = async () => {
      await searchWithAdditionalLoading(false);
    };

    onMounted(async () => {
      if (Object.keys(route.query).length > 0) {
        await initSearch();
      }
    });

    return {
      count,
      form,
      matches,
      searchTask,
      totalCount,
      hasLoadMore,
      initSearch,
      loadMore,
    };
  },
});
</script>
