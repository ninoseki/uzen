<template>
  <div>
    <div v-if="hasSnapshots" class="buttons">
      <b-button
        v-for="snapshot in uniqueSnapshots"
        v-bind:key="snapshot.id"
        tag="router-link"
        :to="{ name: 'Snapshot', params: { id: snapshot.id } }"
        type="is-info"
      >
        {{ snapshot.hostname }} ({{ snapshot.createdAt.split("T")[0] }})
      </b-button>
    </div>
    <div v-else>
      N/A
    </div>
  </div>
</template>

<script lang="ts">
import { Component, Prop, Vue } from "vue-property-decorator";

import { Snapshot } from "@/types";

@Component
export default class Buttons extends Vue {
  @Prop() private snapshots!: Snapshot[];

  get uniqueSnapshots(): Snapshot[] {
    let snapshots: Snapshot[] = [];
    const memo = new Set();
    for (const snapshot of this.snapshots) {
      if (!memo.has(snapshot.id)) {
        snapshots = snapshots.concat(snapshot);
      }
      memo.add(snapshot.id);
    }
    return snapshots;
  }

  get hasSnapshots(): boolean {
    return this.snapshots.length > 0;
  }
}
</script>
