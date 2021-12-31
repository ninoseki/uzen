<template>
  <div>
    <div class="box">
      <Form ref="form" :name="name" :type="type" :source="source" />

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
      v-if="searchTask.isError"
    ></Error>

    <h2 v-if="count !== undefined">
      Search results ({{ count }} / {{ totalCount }})
    </h2>

    <RulesTable v-bind:rules="rules" />

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
import { useRouteQuery } from "@vueuse/router";
import { defineComponent, onMounted, Ref, ref } from "vue";
import { useRoute, useRouter } from "vue-router";

import Form from "@/components/rule/Form.vue";
import RulesTable from "@/components/rule/Table.vue";
import Error from "@/components/ui/SimpleError.vue";
import Loading from "@/components/ui/SimpleLoading.vue";
import { Rule } from "@/types";
import { DEFAULT_OFFSET, DEFAULT_PAGE_SIZE, hasLoadMore } from "@/utils/form";
import { generateSearchRulesTask } from "@/api-helper";

export default defineComponent({
  name: "RulesSearch",
  components: {
    Error,
    Form,
    Loading,
    RulesTable,
  },
  setup() {
    const route = useRoute();
    const router = useRouter();
    const options = { route, router };

    const name = useRouteQuery("name", undefined, options) as Ref<
      string | undefined
    >;
    const type = useRouteQuery("name", undefined, options) as Ref<
      string | undefined
    >;
    const source = useRouteQuery("name", undefined, options) as Ref<
      string | undefined
    >;

    const rules = ref<Rule[]>([]);
    const count = ref<number | undefined>(undefined);
    const totalCount = ref(0);

    let size = DEFAULT_PAGE_SIZE;
    let offset = DEFAULT_OFFSET;

    const form = ref<InstanceType<typeof Form>>();

    const resetPagination = () => {
      rules.value = [];
      count.value = undefined;
      size = DEFAULT_PAGE_SIZE;
      offset = DEFAULT_OFFSET;
    };

    const searchTask = generateSearchRulesTask();

    const search = async () => {
      const params = form.value?.filtersParams() || {};
      params["size"] = size;
      params["offset"] = offset;
      return await searchTask.perform(params);
    };

    const searchWithAdditionalLoading = async (additionalLoading = false) => {
      if (!additionalLoading) {
        resetPagination();
      }

      const res = await search();

      rules.value = rules.value.concat(res.results);
      count.value = rules.value.length;

      if (!additionalLoading) {
        totalCount.value = res.total;
      }

      return;
    };

    const loadMore = async () => {
      offset += size;
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
      name,
      rules,
      searchTask,
      source,
      totalCount,
      type,
      hasLoadMore,
      initSearch,
      loadMore,
    };
  },
});
</script>
