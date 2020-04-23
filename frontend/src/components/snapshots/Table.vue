<template>
  <div class="box table-container" v-if="hasSnapshots()">
    <b-table :data="snapshots">
      <template slot-scope="props">
        <b-table-column field="url" label="URL">
          <strong>URL:</strong>
          <router-link
            :to="{
              name: 'Snapshot',
              params: { id: props.row.id, yaraResult: props.row.yaraResult },
            }"
          >
            {{ props.row.url }}
          </router-link>
          <p>(<strong>Submitted URL:</strong> {{ props.row.submittedUrl }})</p>
        </b-table-column>

        <b-table-column field="ipAddress" label="IP address">
          {{ props.row.ipAddress }}
        </b-table-column>

        <b-table-column field="asn" label="ASN">
          {{ props.row.asn.split(" ")[0] }}
        </b-table-column>

        <b-table-column field="server" label="Server">
          {{ props.row.server }}
        </b-table-column>

        <b-table-column field="createdAt" label="Created on">
          {{ props.row.createdAt.split("T")[0] }}
        </b-table-column>
      </template>
    </b-table>
  </div>
</template>

<script lang="ts">
import { Component, Prop, Vue } from "vue-property-decorator";
import axios, { AxiosError } from "axios";

import { Snapshot, SnapshotWithYaraResult } from "@/types";

@Component
export default class Table extends Vue {
  @Prop() private snapshots!: Snapshot[] | SnapshotWithYaraResult[];

  hasSnapshots(): boolean {
    return this.snapshots.length > 0;
  }
}
</script>
