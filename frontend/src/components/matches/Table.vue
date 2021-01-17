<template>
  <div class="box table-container" v-if="matches.length > 0">
    <b-table :data="matches">
      <b-table-column field="snapshot" label="Snapshot" v-slot="props">
        <router-link
          :to="{
            name: 'Snapshot',
            params: { id: props.row.snapshot.id },
          }"
        >
          {{ truncate(props.row.snapshot.url) }}
        </router-link>
        <p v-if="props.row.script">({{ props.row.script.url }})</p>
      </b-table-column>

      <b-table-column field="rule" label="Matched rule" v-slot="props">
        <router-link
          :to="{
            name: 'Rule',
            params: { id: props.row.rule.id },
          }"
        >
          {{ props.row.rule.name }}
        </router-link>
      </b-table-column>

      <b-table-column field="matches" label="Matches" v-slot="props">
        <pre><code class="json">{{ props.row.matches }}</code></pre>
      </b-table-column>

      <b-table-column field="createdAt" label="Created at" v-slot="props">
        <DatetimeWithDiff v-bind:datetime="props.row.createdAt" />
      </b-table-column>
    </b-table>
  </div>
</template>

<script lang="ts">
import { defineComponent, onUpdated, PropType } from "@vue/composition-api";

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
  setup(_, context) {
    onUpdated(() => {
      highlightCodeBlocks(context);
    });

    return { truncate };
  },
});
</script>
