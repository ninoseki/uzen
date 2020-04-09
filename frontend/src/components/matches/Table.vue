<template>
  <div class="box" v-if="hasMatches()">
    <b-table :data="matches">
      <template slot-scope="props">
        <b-table-column field="id" label="ID" width="40" numeric>
          {{ props.row.id }}
        </b-table-column>

        <b-table-column field="snapshot" label="Snapshot">
          <router-link
            :to="{
              name: 'Snapshot',
              params: { id: props.row.snapshot.id },
            }"
          >
            {{ props.row.snapshot.url }}
          </router-link>
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
          <pre>{{ props.row.matches }}</pre>
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

import { Match } from "@/types";

@Component
export default class Table extends Vue {
  @Prop() private matches!: Match[];

  hasMatches(): boolean {
    return this.matches.length > 0;
  }
}
</script>
