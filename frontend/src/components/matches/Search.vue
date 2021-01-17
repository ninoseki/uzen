<template>
  <div>
    <Loading v-if="searchTask.isRunning"></Loading>
    <Error
      :error="searchTask.last.error.response.data"
      v-else-if="searchTask.isError && searchTask.last !== undefined"
    ></Error>

    <div class="box">
      <Form ref="form" :ruleId="ruleId" :snapshotId="snapshotId" />

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

    <h2 v-if="count !== undefined">
      Search results ({{ count }} / {{ totalCount }})
    </h2>

    <MatchesTable v-bind:matches="matches" />

    <b-button
      v-if="hasLoadMore(count, totalCount)"
      type="is-dark"
      @click="loadMore"
      >Load more...</b-button
    >
  </div>
</template>

<script lang="ts">
import { defineComponent, onMounted, ref } from "@vue/composition-api";
import { useAsyncTask } from "vue-concurrency";

import { API } from "@/api";
import Form from "@/components/matches/Form.vue";
import MatchesTable from "@/components/matches/Table.vue";
import Error from "@/components/ui/Error.vue";
import Loading from "@/components/ui/Loading.vue";
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
  setup(_, context) {
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
      oldestCreatedAt = matches.value[count.value - 1].createdAt;

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
      if (Object.keys(context.root.$route.query).length > 0) {
        initSearch();
      }
    });

    return {
      form,
      initSearch,
      matches,
      count,
      totalCount,
      loadMore,
      hasLoadMore,
      searchTask,
    };
  },
});
</script>
