<template>
  <div class="table-container" v-if="jobStatus.definition !== null">
    <table class="table is-completely-borderless">
      <tbody>
        <tr>
          <th>Submitted URL</th>
          <td>
            {{ truncate(jobStatus.definition.payload.url, 48) }}
          </td>
        </tr>
        <tr>
          <th>Enqueue time</th>
          <td>
            <DatetimeWithDiff
              :datetime="jobStatus.definition.enqueueTime"
            ></DatetimeWithDiff>
          </td>
        </tr>
      </tbody>
    </table>
  </div>
</template>

<script lang="ts">
import { defineComponent, PropType } from "vue";

import DatetimeWithDiff from "@/components/ui/DatetimeWithDiff.vue";
import { SnapshotJobStatus } from "@/types";
import { truncate } from "@/utils/truncate";

export default defineComponent({
  name: "SnapshotJob",
  components: {
    DatetimeWithDiff,
  },
  props: {
    jobStatus: {
      type: Object as PropType<SnapshotJobStatus>,
      required: true,
    },
  },
  setup() {
    return { truncate };
  },
});
</script>
