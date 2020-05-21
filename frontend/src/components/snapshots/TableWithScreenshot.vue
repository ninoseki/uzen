<template>
  <div v-if="hasSnapshots()">
    <b-table :data="snapshots">
      <template slot-scope="props">
        <b-table-column field="url" label="URL">
          <p>
            <strong>URL:</strong>
            <router-link
              :to="{
                name: 'Snapshot',
                params: { id: props.row.id, yaraResult: props.row.yaraResult },
              }"
            >
              {{ props.row.url }}
            </router-link>
          </p>
          <p>(<strong>Submitted URL:</strong> {{ props.row.submittedUrl }})</p>
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
          <p class="is-size-7">
            <strong>SHA256:</strong> {{ props.row.sha256 }}
          </p>
        </b-table-column>

        <b-table-column field="createdAt" label="Created at">
          <DatetimeWithDiff v-bind:datetime="props.row.createdAt" />
        </b-table-column>

        <b-table-column field="screenshot" label="Screenshot">
          <Screenshot v-bind:snapshot_id="props.row.id" />
        </b-table-column>
      </template>
    </b-table>
  </div>
</template>

<script lang="ts">
import { Component, Prop, Vue } from "vue-property-decorator";

import { Snapshot } from "@/types";

import Screenshot from "@/components/screenshots/Screenshot.vue";
import DatetimeWithDiff from "@/components/ui/DatetimeWithDiff.vue";

@Component({
  components: {
    Screenshot,
    DatetimeWithDiff,
  },
})
export default class TableWithScreenshot extends Vue {
  @Prop() private snapshots!: Snapshot[];

  hasSnapshots(): boolean {
    return this.snapshots.length > 0;
  }
}
</script>

<style scoped>
.table img {
  width: 180px;
}
</style>
