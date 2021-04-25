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
    <Error
      :error="scanTask.last.error.response.data"
      v-if="scanTask.isError && scanTask.last !== undefined"
    ></Error>
  </div>
</template>

<script lang="ts">
import { defineComponent, ref } from "@vue/composition-api";
import { useAsyncTask } from "vue-concurrency";

import { API } from "@/api";
import SnapshotForm from "@/components/snapshot/SearchForm.vue";
import Error from "@/components/ui/Error.vue";
import BasicForm from "@/components/yara/BasicForm.vue";
import { Job, TargetTypes, YaraScanPayload } from "@/types";

export default defineComponent({
  name: "YaraForm",
  components: {
    BasicForm,
    SnapshotForm,
    Error,
  },
  setup(_, context) {
    const source = ref("");
    const target = ref<TargetTypes>("html");

    const form = ref<InstanceType<typeof SnapshotForm>>();

    const scanTask = useAsyncTask<Job, []>(async () => {
      // get parameters from the child component
      const params = form.value?.filtersParams() || {};

      // get total count of snapshots and set it as a size
      try {
        const totalCount = await API.getTotalSnapshotCount();
        params["size"] = totalCount.count;
      } catch {
        // do nothing;
      }

      const payload: YaraScanPayload = {
        source: source.value,
        target: target.value,
      };

      return await API.yaraScan(payload, params);
    });

    const scan = async () => {
      const job = await scanTask.perform();
      context.root.$router.push({ path: `/jobs/yara/${job.id}` });
    };

    return { source, target, form, scanTask, scan };
  },
});
</script>
