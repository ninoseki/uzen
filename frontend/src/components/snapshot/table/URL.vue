<template>
  <div>
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
      {{ countryCodeToEmoji(snapshot.countryCode) }} - <strong>ASN:</strong>
      {{ snapshot.asn.split(" ")[0] }}
    </p>

    <p class="is-size-7"><strong>Status:</strong> {{ snapshot.status }}</p>

    <p class="is-size-7" v-if="'similarity' in snapshot">
      <strong>Similarity:</strong>
      {{ numeral(snapshot.similarity).format("0.00%") }}
    </p>
  </div>
</template>

<script lang="ts">
import numeral from "numeral";
import { defineComponent, PropType } from "vue";

import {
  Snapshot,
  SnapshotWithSimilarity,
  SnapshotWithYaraResult,
} from "@/types";
import { countryCodeToEmoji } from "@/utils/country";
import { truncate } from "@/utils/truncate";

export default defineComponent({
  name: "SnapshotTableURL",
  props: {
    snapshot: {
      type: Object as PropType<
        Snapshot | SnapshotWithYaraResult | SnapshotWithSimilarity
      >,
      required: true,
    },
  },
  setup() {
    return { truncate, numeral, countryCodeToEmoji };
  },
});
</script>
