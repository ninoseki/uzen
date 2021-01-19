<template>
  <div>
    <div class="box">
      <BasicForm :source.sync="source" :target.sync="target" />
      <hr />
      <SnapshotForm ref="form" />
      <br />
      <div class="has-text-centered">
        <b-button
          type="is-light"
          icon-pack="fas"
          icon-left="search"
          @click="scan"
          >Scan</b-button
        >
      </div>
    </div>
    <h2 v-if="hasCount()">{{ count }} snapshots found</h2>

    <Loading v-if="scanTask.isRunning"></Loading>
    <Error
      :error="scanTask.last.error.response.data"
      v-else-if="scanTask.isError && scanTask.last !== undefined"
    ></Error>
    <SnapshotTable
      :snapshots="scanTask.last.value || []"
      v-else-if="scanTask.last !== undefined"
    ></SnapshotTable>
  </div>
</template>

<script lang="ts">
import { defineComponent, ref } from "@vue/composition-api";
import { useAsyncTask } from "vue-concurrency";

import { API } from "@/api";
import SnapshotForm from "@/components/snapshot/SearchForm.vue";
import SnapshotTable from "@/components/snapshot/Table.vue";
import Error from "@/components/ui/Error.vue";
import Loading from "@/components/ui/Loading.vue";
import BasicForm from "@/components/yara/BasicForm.vue";
import { SnapshotWithYaraResult, TargetTypes, YaraScanPyalod } from "@/types";

export default defineComponent({
  name: "YaraForm",
  components: {
    Error,
    Loading,
    BasicForm,
    SnapshotForm,
    SnapshotTable,
  },
  setup() {
    const source = ref("");
    const target = ref<TargetTypes>("html");
    const count = ref<number | undefined>(undefined);

    const form = ref<InstanceType<typeof SnapshotForm>>();

    const scanTask = useAsyncTask<SnapshotWithYaraResult[], []>(async () => {
      // reset the count
      count.value = undefined;

      // get parameters from the child component
      const params = form.value?.filtersParams() || {};

      // get total count of snapshots and set it as a size
      try {
        const totalCount = await API.getTotalSnapshotCount();
        params["size"] = totalCount.count;
      } catch {
        // do nothing;
      }

      const payload: YaraScanPyalod = {
        source: source.value,
        target: target.value,
      };

      const res = await API.yaraScan(payload, params);
      count.value = res.length;

      return res;
    });

    const scan = () => {
      scanTask.perform();
    };

    const hasCount = () => {
      return count.value !== undefined;
    };

    return { source, target, count, form, scanTask, hasCount, scan };
  },
});
</script>
