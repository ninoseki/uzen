<template>
  <div class="box table-container" ref="root" v-if="matches.length > 0">
    <table class="table is-fullwidth">
      <thead>
        <tr>
          <th>Snapshot</th>
          <th>Matched rule</th>
          <th>Matches</th>
          <th>Created at</th>
        </tr>
      </thead>
      <tbody>
        <tr v-for="match in matches" :key="match.id">
          <td>
            <router-link
              :to="{
                name: 'Snapshot',
                params: { id: match.snapshot.id },
              }"
            >
              {{ truncate(match.snapshot.url) }}
            </router-link>
            <p v-if="match.script">({{ match.script.url }})</p>
          </td>
          <td>
            <router-link
              :to="{
                name: 'Rule',
                params: { id: match.rule.id },
              }"
            >
              {{ match.rule.name }}
            </router-link>
          </td>
          <td>
            <pre><code class="json">{{ match.matches }}</code></pre>
          </td>
          <td>
            <DatetimeWithDiff v-bind:datetime="match.createdAt" />
          </td>
        </tr>
      </tbody>
    </table>
  </div>
</template>

<script lang="ts">
import { defineComponent, onUpdated, PropType, ref } from "vue";

import DatetimeWithDiff from "@/components/ui/DatetimeWithDiff.vue";
import { Match } from "@/types";
import { highlightCodeBlocks } from "@/utils/highlight";
import { truncate } from "@/utils/truncate";

export default defineComponent({
  name: "MatchesTable",
  components: {
    DatetimeWithDiff,
  },
  props: {
    matches: {
      type: Array as PropType<Match[]>,
      required: true,
    },
  },
  setup() {
    const root = ref<HTMLElement | null>(null);

    onUpdated(() => {
      if (root.value !== null) {
        highlightCodeBlocks(root.value);
      }
    });

    return { root, truncate };
  },
});
</script>
