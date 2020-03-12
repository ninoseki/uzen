<template>
  <div class="box" v-if="hashSnapshot()">
    <b-table :data="snapshots">
      <template slot-scope="props">
        <b-table-column field="id" label="ID" width="40" numeric>
          {{ props.row.id }}
        </b-table-column>

        <b-table-column field="url" label="URL">
          <router-link :to="`/snapshots/${props.row.id}`">
            {{ props.row.url }}
          </router-link>
        </b-table-column>

        <b-table-column field="hostname" label="Hostname">
          {{ props.row.hostname }}
        </b-table-column>

        <b-table-column field="ip_address" label="IP address">
          {{ props.row.ip_address }}
        </b-table-column>

        <b-table-column field="asn" label="ASN">
          {{ props.row.asn.split(" ")[0] }}
        </b-table-column>

        <b-table-column field="server" label="Server">
          {{ props.row.server }}
        </b-table-column>

        <b-table-column field="created_at" label="Created on">
          {{ props.row.created_at.split("T")[0] }}
        </b-table-column>
      </template>
    </b-table>
  </div>
</template>

<script lang="ts">
import { Component, Prop, Vue } from "vue-property-decorator";
import axios, { AxiosError } from "axios";

import { Snapshot } from "@/types";

@Component
export default class Table extends Vue {
  @Prop() private snapshots!: Snapshot[];

  hashSnapshot(): boolean {
    return this.snapshots.length > 0;
  }
}
</script>
