<template>
  <div class="box table-container" v-if="hasSnapshots">
    <b-table :data="snapshots">
      <b-table-column field="url" label="URL" v-slot="props">
        <p>
          <strong>URL:</strong>
          <router-link
            :to="{
              name: 'Snapshot',
              params: { id: props.row.id, yaraResult: props.row.yaraResult },
            }"
          >
            {{ truncate(props.row.url) }}
          </router-link>
        </p>
        <p>
          (<strong>Submitted URL:</strong>
          {{ truncate(props.row.submittedUrl) }})
        </p>
        <p class="is-size-7">
          <strong>IP address:</strong> {{ props.row.ipAddress }} -
          <strong>ASN:</strong> {{ props.row.asn.split(" ")[0] }}
        </p>
        <p class="is-size-7">
          <strong>Status:</strong> {{ props.row.status }} -
          <strong>Server:</strong>
          {{ props.row.server || "N/A" }} -
          <strong>Content length:</strong>
          {{ props.row.contentLength || "N/A" }}
        </p>
        <p class="is-size-7"><strong>SHA256:</strong> {{ props.row.sha256 }}</p>
      </b-table-column>

      <b-table-column field="createdAt" label="Created at" v-slot="props">
        <DatetimeWithDiff :datetime="props.row.createdAt" />
      </b-table-column>
    </b-table>
  </div>
</template>

<script lang="ts">
import { computed, defineComponent, PropType } from "@vue/composition-api";

import DatetimeWithDiff from "@/components/ui/DatetimeWithDiff.vue";
import { Snapshot, SnapshotWithYaraResult } from "@/types";
import { truncate } from "@/utils/truncate";

export default defineComponent({
  name: "SnapshotTable",
  props: {
    snapshots: {
      type: Array as PropType<Snapshot[] | SnapshotWithYaraResult[]>,
      required: true,
    },
  },
  components: {
    DatetimeWithDiff,
  },
  setup(props) {
    const hasSnapshots = computed((): boolean => {
      return props.snapshots.length > 0;
    });

    return { hasSnapshots, truncate };
  },
});
</script>
