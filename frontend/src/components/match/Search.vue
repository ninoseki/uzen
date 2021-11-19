<template>
  <div>
    <div class="box">
      <Form ref="form" :ruleId="ruleId" :snapshotId="snapshotId" />

      <br />

      <div class="has-text-centered">
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
import { useAsyncTask } from "vue-concurrency";
import { useRoute } from "vue-router";

import { API } from "@/api";
import Form from "@/components/match/Form.vue";
import MatchesTable from "@/components/match/Table.vue";
import Error from "@/components/ui/SimpleError.vue";
import Loading from "@/components/ui/SimpleLoading.vue";
import { Match, MatchSearchResults } from "@/types";
import {
  DEFAULT_PAGE_SIZE,
  hasLoadMore,
  minDatetime,
  nowDatetime,
} from "@/utils/form";

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
      totalCount.value = 0;
      size = DEFAULT_PAGE_SIZE;
      oldestCreatedAt = nowDatetime();
    };

    const searchTask = useAsyncTask<MatchSearchResults, []>(async () => {
      const params = form.value?.filtersParams() || {};
      params["size"] = size;
      params["toAt"] = minDatetime(params["toAt"], oldestCreatedAt);

      return await API.searchMatches(params);
    });

    const search = async (additonalLoading = false) => {
      if (!additonalLoading) {
        resetPagination();
      }

      const res = await searchTask.perform();

      matches.value = matches.value.concat(res.results);
      count.value = matches.value.length;

      if (matches.value.length > 0) {
        oldestCreatedAt = matches.value[count.value - 1].createdAt;
      }

      if (!additonalLoading) {
        totalCount.value = res.total;
      }

      return;
    };

    const loadMore = () => {
      search(true);
    };

    const initSearch = () => {
      search(false);
    };

    onMounted(() => {
      if (Object.keys(route.query).length > 0) {
        initSearch();
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
