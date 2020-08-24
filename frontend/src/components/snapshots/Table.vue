<template>
  <div class="box table-container" v-if="hasSnapshots">
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
            {{ props.row.url | truncate }}
          </router-link>
        </p>
        <p>
          (<strong>Submitted URL:</strong>
          {{ props.row.submittedUrl | truncate }})
        </p>
        <p class="is-size-7">
          <strong>IP address:</strong> {{ props.row.ipAddress }} -
          <strong>ASN:</strong> {{ props.row.asn.split(" ")[0] }}
        </p>
        <p class="is-size-7">
          <strong>Status:</strong> {{ props.row.status }} -
          <strong>Server:</strong>
          {{ props.row.server || "N/A" }} -
          <strong>Content length:</strong>
          {{ props.row.contentLength || "N/A" }}
        </p>
        <p class="is-size-7"><strong>SHA256:</strong> {{ props.row.sha256 }}</p>
      </b-table-column>

      <b-table-column field="createdAt" label="Created at" v-slot="props">
        <DatetimeWithDiff v-bind:datetime="props.row.createdAt" />
      </b-table-column>
    </b-table>
  </div>
</template>

<script lang="ts">
import { Component, Prop, Vue } from "vue-property-decorator";

import DatetimeWithDiff from "@/components/ui/DatetimeWithDiff.vue";
import { Snapshot, SnapshotWithYaraResult } from "@/types";

@Component({
  components: {
    DatetimeWithDiff,
  },
})
export default class Table extends Vue {
  @Prop() private snapshots!: Snapshot[] | SnapshotWithYaraResult[];

  get hasSnapshots(): boolean {
    return this.snapshots.length > 0;
  }
}
</script>
