<template>
  <div>
    <div v-if="getHARTask.last && getHARTask.last.value && !getHARTask.isError">
      <nav class="level">
        <div class="level-left"></div>
        <div class="level-right">
          <p class="level-item">
            <button class="button" @click="download">
              <span class="icon"><i class="fas fa-download"></i></span>
              <span>Download</span>
            </button>
          </p>
        </div>
      </nav>
      <HarTable :entries="getHARTask.last.value.data.log.entries"></HarTable>
    </div>
    <NA v-else></NA>
  </div>
</template>

<script lang="ts">
import { defineComponent } from "@vue/composition-api";
import fileDownload from "js-file-download";
import { useAsyncTask } from "vue-concurrency";

import { API } from "@/api";
import HarTable from "@/components/har/Table.vue";
import NA from "@/components/ui/NA.vue";
import { HAR } from "@/types";

export default defineComponent({
  name: "HAR",
  components: { NA, HarTable },
  props: {
    snapshotId: {
      type: String,
      required: true,
    },
  },
  setup(props) {
    const getHARTask = useAsyncTask<HAR, []>(async () => {
      return await API.getHAR(props.snapshotId);
    });

    getHARTask.perform();

    const download = () => {
      const data = JSON.stringify(getHARTask.last?.value?.data || {});
      fileDownload(data, `${props.snapshotId}.har`, "application/json");
    };

    return { getHARTask, download };
  },
});
</script>
