<template>
  <div>
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
  </div>
</template>

<script lang="ts">
import { defineComponent, onMounted, ref } from "vue";
import { useRoute } from "vue-router";

import Form from "@/components/match/Form.vue";
import MatchesTable from "@/components/match/Table.vue";
import Error from "@/components/ui/SimpleError.vue";
import Loading from "@/components/ui/SimpleLoading.vue";
import { Match } from "@/types";
import {
  DEFAULT_PAGE_SIZE,
  hasLoadMore,
  minDatetime,
  nowDatetime,
} from "@/utils/form";
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

    let oldestCreatedAt: string | undefined = undefined;
    let size = DEFAULT_PAGE_SIZE;

    const form = ref<InstanceType<typeof Form>>();

    const resetPagination = () => {
      matches.value = [];
      count.value = undefined;
      size = DEFAULT_PAGE_SIZE;
      oldestCreatedAt = nowDatetime();
    };

    const searchTask = generateSearchMatchesTask();

    const search = async () => {
      const params = form.value?.filtersParams() || {};
      params["size"] = size;
      params["toAt"] = minDatetime(params["toAt"], oldestCreatedAt);

      return await searchTask.perform(params);
    };

    const searchWithAdditionalLoading = async (additionalLoading = false) => {
      if (!additionalLoading) {
        resetPagination();
      }

      const res = await search();

      matches.value = matches.value.concat(res.results);
      count.value = matches.value.length;

      if (matches.value.length > 0) {
        oldestCreatedAt = matches.value[count.value - 1].createdAt;
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
