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
            <strong>Status:</strong> {{ props.row.status }} /
            <strong>Server:</strong>
            {{ props.row.server || "N/A" }} /
            <strong>Content length:</strong>
            {{ props.row.contentLength || "N/A" }}
          </p>
          <p class="is-size-7">
            <strong>SHA256:</strong> {{ props.row.sha256 }}
          </p>
        </b-table-column>

        <b-table-column field="ipAddress" label="IP address">
          {{ props.row.ipAddress }}
        </b-table-column>

        <b-table-column field="asn" label="ASN">
          {{ props.row.asn.split(" ")[0] }}
        </b-table-column>

        <b-table-column field="createdAt" label="Created on">
          {{ props.row.createdAt.split("T")[0] }}
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
import axios, { AxiosError } from "axios";

import { Snapshot } from "@/types";

import Screenshot from "@/components/screenshots/Screenshot.vue";

@Component({
  components: {
    Screenshot,
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
