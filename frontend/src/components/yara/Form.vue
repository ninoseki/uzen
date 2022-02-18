<template>
  <div>
    <div class="box">
      <article class="message is-info">
        <div class="message-body">Scan snapshots with YARA</div>
      </article>

      <BasicForm v-model:source="source" v-model:target="target" />

      <hr />

      <SnapshotForm ref="form" />

      <div class="has-text-centered mt-5">
        <button class="button is-light" @click="scan">
          <span class="icon">
            <i class="fas fa-search"></i>
          </span>
          <span>Scan</span>
        </button>
      </div>
    </div>

    <Error
      :error="scanTask.last.error.response.data"
      v-if="scanTask.isError && scanTask.last"
    ></Error>
  </div>
</template>

<script lang="ts">
import { defineComponent, ref } from "vue";
import { useRouter } from "vue-router";

import { API } from "@/api";
import SnapshotForm from "@/components/snapshot/SearchForm.vue";
import Error from "@/components/ui/SimpleError.vue";
import BasicForm from "@/components/yara/BasicForm.vue";
import { TargetTypes, YaraScanPayload } from "@/types";
import { generateYaraScanTask } from "@/api-helper";

export default defineComponent({
  name: "YaraForm",
  components: {
    BasicForm,
    SnapshotForm,
    Error,
  },
  setup() {
    const router = useRouter();

    const source = ref("");
    const target = ref<TargetTypes>("html");

    const form = ref<InstanceType<typeof SnapshotForm>>();

    const scanTask = generateYaraScanTask();
    const scan = async () => {
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

      const job = await scanTask.perform(payload, params);

      router.push({ path: `/jobs/yara/${job.id}` });
    };

    return { source, target, form, scanTask, scan };
  },
});
</script>
