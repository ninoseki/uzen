<template>
  <div class="table-container">
    <table class="table is-narrow is-hoverable is-fullwidth">
      <thead>
        <tr>
          <th>Method</th>
          <th>Path</th>
          <th>Status</th>
          <th>Size</th>
          <th>MIME type</th>
          <th>IP address</th>
        </tr>
      </thead>
      <tbody>
        <Row
          v-for="(entry, index) in entries"
          :key="index"
          :entry="entry"
        ></Row>
      </tbody>
    </table>
  </div>
</template>

<script lang="ts">
import * as harFormat from "har-format";
import { defineComponent, PropType } from "vue";

import Row from "@/components/har/Row.vue";

export default defineComponent({
  name: "HarTable",
  props: {
    entries: {
      type: Array as PropType<harFormat.Entry[]>,
      required: true,
    },
  },
  components: { Row },
});
</script>
