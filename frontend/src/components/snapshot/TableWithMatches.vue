<template>
  <div v-if="hasSnapshots" ref="root">
    <table class="table is-fullwidth">
      <thead>
        <tr>
          <th>URL</th>
          <th>Created at</th>
          <th>Matches</th>
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
                {{ snapshot.url }}
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
          </td>
          <td>
            <DatetimeWithDiff :datetime="snapshot.createdAt" />
          </td>
          <td>
            <pre><code class="json">{{ snapshot.yaraResult?.matches }}</code></pre>
          </td>
        </tr>
      </tbody>
    </table>
  </div>
</template>

<script lang="ts">
import { computed, defineComponent, PropType, ref, watchEffect } from "vue";

import DatetimeWithDiff from "@/components/ui/DatetimeWithDiff.vue";
import { SnapshotWithYaraResult } from "@/types/job";
import { countryCodeToEmoji } from "@/utils/country";
import { highlightCodeBlocks } from "@/utils/highlight";
import { truncate } from "@/utils/truncate";

export default defineComponent({
  name: "SnapshotTableWithYaraResult",
  props: {
    snapshots: {
      type: Array as PropType<SnapshotWithYaraResult[]>,
      required: true,
    },
  },
  components: {
    DatetimeWithDiff,
  },
  setup(props) {
    const root = ref<HTMLElement | null>(null);

    const hasSnapshots = computed((): boolean => {
      return props.snapshots.length > 0;
    });

    watchEffect(() => {
      if (root.value !== null) {
        highlightCodeBlocks(root.value);
      }
    });

    return { hasSnapshots, truncate, countryCodeToEmoji, root };
  },
});
</script>
