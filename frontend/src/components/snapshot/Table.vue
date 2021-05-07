<template>
  <div class="box table-container" v-if="$props.snapshots.length > 0">
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

        <p class="is-size-7" v-if="'similarity' in props.row">
          <strong>Similarity:</strong>
          {{ toPercentString(props.row.similarity) }}
        </p>
      </b-table-column>

      <b-table-column field="createdAt" label="Created at" v-slot="props">
        <DatetimeWithDiff :datetime="props.row.createdAt" />
      </b-table-column>
    </b-table>
  </div>
</template>

<script lang="ts">
import { defineComponent, PropType } from "@vue/composition-api";

import DatetimeWithDiff from "@/components/ui/DatetimeWithDiff.vue";
import {
  Snapshot,
  SnapshotWithSimilarity,
  SnapshotWithYaraResult,
} from "@/types";
import { countryCodeToEmoji } from "@/utils/country";
import { truncate } from "@/utils/truncate";

export default defineComponent({
  name: "SnapshotTable",
  props: {
    snapshots: {
      type: Array as PropType<
        Snapshot[] | SnapshotWithYaraResult[] | SnapshotWithSimilarity[]
      >,
      required: true,
    },
  },
  components: {
    DatetimeWithDiff,
  },
  setup() {
    const toPercentString = (n: number) => {
      return `${Math.floor(n * 100)}%`;
    };

    return { truncate, countryCodeToEmoji, toPercentString };
  },
});
</script>
