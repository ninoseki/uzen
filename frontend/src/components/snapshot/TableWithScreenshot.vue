<template>
  <div v-if="hasSnapshots">
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
            {{ props.row.url }}
          </router-link>
        </p>
        <p class="is-size-7">
          <strong>Submitted URL:</strong>
          {{ truncate(props.row.submittedUrl) }}
        </p>
        <p class="is-size-7">
          <strong>IP address:</strong> {{ props.row.ipAddress }}
          {{ countryCodeToEmoji(props.row.countryCode) }} -
          <strong>ASN:</strong> {{ props.row.asn.split(" ")[0] }}
        </p>
        <p class="is-size-7"><strong>Status:</strong> {{ props.row.status }}</p>
      </b-table-column>

      <b-table-column field="createdAt" label="Created at" v-slot="props">
        <DatetimeWithDiff :datetime="props.row.createdAt" />
      </b-table-column>

      <b-table-column field="screenshot" label="Screenshot" v-slot="props">
        <Screenshot :snapshotId="props.row.id" />
      </b-table-column>
    </b-table>
  </div>
</template>

<script lang="ts">
import { computed, defineComponent, PropType } from "@vue/composition-api";

import Screenshot from "@/components/screenshot/Screenshot.vue";
import DatetimeWithDiff from "@/components/ui/DatetimeWithDiff.vue";
import { Snapshot } from "@/types";
import { countryCodeToEmoji } from "@/utils/country";
import { truncate } from "@/utils/truncate";

export default defineComponent({
  name: "SnapshotTableWithScreenshot",
  props: {
    snapshots: {
      type: Array as PropType<Snapshot[]>,
      required: true,
    },
  },
  components: {
    DatetimeWithDiff,
    Screenshot,
  },
  setup(props) {
    const hasSnapshots = computed((): boolean => {
      return props.snapshots.length > 0;
    });

    return { hasSnapshots, truncate, countryCodeToEmoji };
  },
});
</script>

<style>
.table img {
  max-width: 180px;
}
</style>
