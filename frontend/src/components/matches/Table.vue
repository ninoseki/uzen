<template>
  <div class="box table-container" v-if="hasMatches()">
    <b-table :data="matches">
      <template slot-scope="props">
        <b-table-column field="snapshot" label="Snapshot">
          <router-link
            :to="{
              name: 'Snapshot',
              params: { id: props.row.snapshot.id },
            }"
          >
            {{ props.row.snapshot.url }}
          </router-link>
          <p v-if="props.row.script">({{ props.row.script.url }})</p>
        </b-table-column>

        <b-table-column field="rule" label="Matched rule">
          <router-link
            :to="{
              name: 'Rule',
              params: { id: props.row.rule.id },
            }"
          >
            {{ props.row.rule.name }}
          </router-link>
        </b-table-column>

        <b-table-column field="matches" label="Matches">
          <pre><code class="json">{{ props.row.matches }}</code></pre>
        </b-table-column>

        <b-table-column field="createdAt" label="Created at">
          <DatetimeWithDiff v-bind:datetime="props.row.createdAt" />
        </b-table-column>
      </template>
    </b-table>
  </div>
</template>

<script lang="ts">
import { Component, Mixin, Mixins } from "vue-mixin-decorator";
import { Prop } from "vue-property-decorator";

import { Match } from "@/types";

import { HighlightMixin } from "@/components/mixins";
import DatetimeWithDiff from "@/components/ui/DatetimeWithDiff.vue";

@Component({
  components: {
    DatetimeWithDiff,
  },
})
export default class Table extends Mixins<HighlightMixin>(HighlightMixin) {
  @Prop() private matches!: Match[];

  hasMatches(): boolean {
    return this.matches.length > 0;
  }

  updated() {
    this.highlightCodeBlocks();
  }
}
</script>
