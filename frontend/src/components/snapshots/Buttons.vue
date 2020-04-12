<template>
  <div>
    <div v-if="hasSnapshots()" class="buttons">
      <b-button
        v-for="snapshot in snapshots"
        v-bind:key="snapshot.id"
        tag="router-link"
        :to="{ name: 'Snapshot', params: { id: snapshot.id } }"
        type="is-info"
      >
        {{ snapshot.hostname }} ({{ snapshot.created_at.split("T")[0] }})
      </b-button>
    </div>
    <div v-else>
      N/A
    </div>
  </div>
</template>

<script lang="ts">
import { Component, Vue, Prop } from "vue-property-decorator";

import { Snapshot } from "@/types";

@Component
export default class Buttons extends Vue {
  @Prop() private snapshots!: Snapshot[];

  hasSnapshots(): boolean {
    return this.snapshots.length > 0;
  }
}
</script>
