<template>
  <div>
    <Loading v-if="searchTask.isRunning"></Loading>
    <Error
      :error="searchTask.last.error.response.data"
      v-else-if="searchTask.isError && searchTask.last !== undefined"
    ></Error>

    <div class="box">
      <Form
        ref="form"
        :name="$route.query.name"
        :type="$route.query.type"
        :source="$route.query.source"
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

    <h2 v-if="count !== undefined">
      Search results ({{ count }} / {{ totalCount }})
    </h2>

    <RulesTable v-bind:rules="rules" />

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
import Form from "@/components/rule/Form.vue";
import RulesTable from "@/components/rule/Table.vue";
import Error from "@/components/ui/Error.vue";
import Loading from "@/components/ui/Loading.vue";
import { Rule, RuleSearchResults } from "@/types";
import { DEFAULT_OFFSET, DEFAULT_PAGE_SIZE, hasLoadMore } from "@/utils/form";

export default defineComponent({
  name: "RulesSearch",
  components: {
    Error,
    Form,
    Loading,
    RulesTable,
  },
  setup(_, context) {
    const rules = ref<Rule[]>([]);
    const count = ref<number | undefined>(undefined);
    const totalCount = ref(0);

    let size = DEFAULT_PAGE_SIZE;
    let offset = DEFAULT_OFFSET;

    const form = ref<InstanceType<typeof Form>>();

    const resetPagination = () => {
      rules.value = [];
      totalCount.value = 0;
      size = DEFAULT_PAGE_SIZE;
      offset = DEFAULT_OFFSET;
    };

    const searchTask = useAsyncTask<RuleSearchResults, []>(async () => {
      const params = form.value?.filtersParams() || {};
      params["size"] = size;
      params["offset"] = offset;
      return await API.searchRules(params);
    });

    const search = async (additonalLoading = false) => {
      if (!additonalLoading) {
        resetPagination();
      }

      const res = await searchTask.perform();

      rules.value = rules.value.concat(res.results);
      count.value = rules.value.length;

      if (!additonalLoading) {
        totalCount.value = res.total;
      }

      return;
    };

    const loadMore = () => {
      offset += size;
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
      rules,
      count,
      totalCount,
      loadMore,
      hasLoadMore,
      searchTask,
    };
  },
});
</script>
