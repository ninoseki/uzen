<template>
  <div>
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
  </div>
</template>

<script lang="ts">
import { useRouteQuery } from "@vueuse/router";
import { defineComponent, onMounted, Ref, ref } from "vue";
import { useAsyncTask } from "vue-concurrency";
import { useRoute, useRouter } from "vue-router";

import { API } from "@/api";
import Form from "@/components/snapshot/SearchForm.vue";
import SnapshotsTable from "@/components/snapshot/Table.vue";
import Error from "@/components/ui/SimpleError.vue";
import Loading from "@/components/ui/SimpleLoading.vue";
import { Snapshot, SnapshotSearchResults } from "@/types";
import {
  DEFAULT_PAGE_SIZE,
  hasLoadMore,
  minDatetime,
  nowDatetime,
} from "@/utils/form";

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

    let oldestCreatedAt: string | undefined = undefined;
    let size = DEFAULT_PAGE_SIZE;

    const form = ref<InstanceType<typeof Form>>();

    const resetPagination = () => {
      snapshots.value = [];
      count.value = undefined;
      size = DEFAULT_PAGE_SIZE;
      oldestCreatedAt = nowDatetime();
    };

    const searchTask = useAsyncTask<SnapshotSearchResults, []>(async () => {
      const params = form.value?.filtersParams() || {};
      params["size"] = size;
      params["toAt"] = minDatetime(params["toAt"], oldestCreatedAt);

      return await API.searchSnapshots(params);
    });

    const search = async (additionalLoading = false) => {
      if (!additionalLoading) {
        resetPagination();
      }

      const res = await searchTask.perform();

      snapshots.value = snapshots.value.concat(res.results);
      count.value = snapshots.value.length;

      if (snapshots.value.length > 0) {
        oldestCreatedAt = snapshots.value[count.value - 1].createdAt;
      }

      if (!additionalLoading) {
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
