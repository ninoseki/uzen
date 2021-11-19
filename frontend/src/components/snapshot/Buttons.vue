<template>
  <div>
    <div v-if="hasSnapshots" class="buttons">
      <button
        class="button is-info"
        v-for="snapshot in uniqueSnapshots"
        :key="snapshot.id"
      >
        <router-link :to="{ name: 'Snapshot', params: { id: snapshot.id } }">
          {{ snapshot.hostname }} ({{
            (snapshot.createdAt || "").split("T")[0]
          }})
        </router-link>
      </button>
    </div>
    <div v-else>N/A</div>
  </div>
</template>

<script lang="ts">
import { computed, defineComponent, PropType } from "vue";

import { Snapshot } from "@/types";

export default defineComponent({
  name: "SnapshotButtons",
  props: {
    snapshots: {
      type: Array as PropType<Snapshot[]>,
      required: true,
    },
  },
  setup(props) {
    const uniqueSnapshots = computed((): Snapshot[] => {
      let snapshots: Snapshot[] = [];
      const memo = new Set();
      for (const snapshot of props.snapshots) {
        if (!memo.has(snapshot.id)) {
          snapshots = snapshots.concat(snapshot);
        }
        memo.add(snapshot.id);
      }
      return snapshots;
    });

    const hasSnapshots = computed((): boolean => {
      return props.snapshots.length > 0;
    });

    return { hasSnapshots, uniqueSnapshots };
  },
});
</script>
