<template>
  <div class="box">
    <Form
      ref="form"
      :asn="asn"
      :hostname="hostname"
      :ipAddress="ipAddress"
      :hash="hash"
      :certificateFingerprint="certificateFingerprint"
      :tag="tag"
    />

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

  <SnapshotsTable v-bind:snapshots="snapshots" />

  <button
    class="button is-dark"
    v-if="hasLoadMore(count, totalCount)"
    @click="loadMore"
  >
    Load more...
  </button>
</template>

<script lang="ts">
import { useRouteQuery } from "@vueuse/router";
import { defineComponent, onMounted, Ref, ref } from "vue";
import { useRoute, useRouter } from "vue-router";

import Form from "@/components/snapshot/SearchForm.vue";
import SnapshotsTable from "@/components/snapshot/Table.vue";
import Error from "@/components/ui/SimpleError.vue";
import Loading from "@/components/ui/SimpleLoading.vue";
import { Snapshot } from "@/types";
import { DEFAULT_PAGE_SIZE, hasLoadMore } from "@/utils/form";
import { generateSearchSnapshotsTask } from "@/api-helper";

export default defineComponent({
  name: "SnapshotSearch",
  components: {
    Error,
    Form,
    Loading,
    SnapshotsTable,
  },
  setup() {
    const route = useRoute();
    const router = useRouter();
    const options = { route, router };

    const snapshots = ref<Snapshot[]>([]);
    const count = ref<number | undefined>(undefined);
    const totalCount = ref(0);
    const searchBefore = ref<string | undefined>(undefined);

    const asn = useRouteQuery("asn", undefined, options) as Ref<
      string | undefined
    >;
    const hostname = useRouteQuery("hostname", undefined, options) as Ref<
      string | undefined
    >;
    const ipAddress = useRouteQuery("ipAddress", undefined, options) as Ref<
      string | undefined
    >;
    const hash = useRouteQuery("hash", undefined, options) as Ref<
      string | undefined
    >;
    const certificateFingerprint = useRouteQuery(
      "certificateFingerprint",
      undefined,
      options
    ) as Ref<string | undefined>;
    const tag = useRouteQuery("tag", undefined, options) as Ref<
      string | undefined
    >;

    const size = DEFAULT_PAGE_SIZE;
    const form = ref<InstanceType<typeof Form>>();

    const resetPagination = () => {
      snapshots.value = [];
      count.value = undefined;
      searchBefore.value = undefined;
    };

    const searchTask = generateSearchSnapshotsTask();

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

      snapshots.value = snapshots.value.concat(res.results);
      count.value = snapshots.value.length;

      if (count.value > 0) {
        searchBefore.value = snapshots.value[count.value - 1].id;
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
      asn,
      certificateFingerprint,
      count,
      form,
      hash,
      hostname,
      ipAddress,
      searchTask,
      snapshots,
      tag,
      totalCount,
      hasLoadMore,
      initSearch,
      loadMore,
    };
  },
});
</script>
