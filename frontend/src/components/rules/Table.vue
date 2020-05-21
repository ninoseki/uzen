<template>
  <div class="box table-container" v-if="hasRules()">
    <b-table :data="rules">
      <template slot-scope="props">
        <b-table-column field="name" label="Name">
          <router-link
            :to="{
              name: 'Rule',
              params: { id: props.row.id },
            }"
          >
            {{ props.row.name }}
          </router-link>
        </b-table-column>

        <b-table-column field="target" label="Target">
          {{ props.row.target }}
        </b-table-column>
      </template>
    </b-table>
  </div>
</template>

<script lang="ts">
import { Component, Prop, Vue } from "vue-property-decorator";

import { Rule } from "@/types";

@Component
export default class Table extends Vue {
  @Prop() private rules!: Rule[];

  hasRules(): boolean {
    return this.rules.length > 0;
  }
}
</script>
