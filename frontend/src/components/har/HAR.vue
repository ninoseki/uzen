<template>
  <div>
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
    <HarTable :entries="har.data.log.entries"></HarTable>
  </div>
</template>

<script lang="ts">
import { defineComponent, PropType } from "@vue/composition-api";
import fileDownload from "js-file-download";

import HarTable from "@/components/har/Table.vue";
import { HAR } from "@/types";

export default defineComponent({
  name: "HAR",
  components: { HarTable },
  props: {
    har: {
      type: Object as PropType<HAR>,
      required: true,
    },
    snapshotId: {
      type: String,
      required: true,
    },
  },
  setup(props) {
    const download = () => {
      const data = JSON.stringify(props.har.data || {});
      fileDownload(data, `${props.snapshotId}.har`, "application/json");
    };

    return { download };
  },
});
</script>
