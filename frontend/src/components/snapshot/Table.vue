<template>
  <div class="box table-container" v-if="$props.snapshots.length > 0">
    <table class="table is-fullwidth">
      <thead>
        <tr>
          <th>URL</th>
          <th>Created at</th>
        </tr>
      </thead>
      <tbody>
        <tr v-for="snapshot in snapshots" :key="snapshot.id">
          <td>
            <p>
              <strong>URL:</strong>
              <router-link
                :to="{
                  name: 'Snapshot',
                  params: {
                    id: snapshot.id,
                  },
                }"
              >
                {{ truncate(snapshot.url) }}
              </router-link>
            </p>
            <p class="is-size-7">
              <strong>Submitted URL:</strong>
              {{ truncate(snapshot.submittedUrl) }}
            </p>
            <p class="is-size-7">
              <strong>IP address:</strong> {{ snapshot.ipAddress }}
              {{ countryCodeToEmoji(snapshot.countryCode) }} -
              <strong>ASN:</strong> {{ snapshot.asn.split(" ")[0] }}
            </p>
            <p class="is-size-7">
              <strong>Status:</strong> {{ snapshot.status }}
            </p>

            <p class="is-size-7" v-if="(snapshot.tags || []).length > 0">
              <strong>Tags:</strong>
              <Tags :tags="snapshot.tags"></Tags>
            </p>

            <p class="is-size-7" v-if="'similarity' in snapshot">
              <strong>Similarity:</strong>
              {{ toPercentString(snapshot.similarity) }}
            </p>
          </td>
          <td>
            <DatetimeWithDiff :datetime="snapshot.createdAt" />
          </td>
        </tr>
      </tbody>
    </table>
  </div>
</template>

<script lang="ts">
import { defineComponent, PropType } from "vue";

import Tags from "@/components/snapshot/Tags.vue";
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
    Tags,
  },
  setup() {
    const toPercentString = (n: number) => {
      return `${Math.floor(n * 100)}%`;
    };

    return { truncate, countryCodeToEmoji, toPercentString };
  },
});
</script>
