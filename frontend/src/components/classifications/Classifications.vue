<template>
  <div class="table-container">
    <b-table :data="classifications">
      <template slot-scope="props">
        <b-table-column field="name" label="Name">
          {{ props.row.name }}
        </b-table-column>

        <b-table-column field="malicious" label="Malicious">
          {{ props.row.malicious }}
        </b-table-column>
      </template>
    </b-table>
  </div>
</template>

<script lang="ts">
import { Component, Vue, Prop } from "vue-property-decorator";

import { Classification } from "@/types";

@Component
export default class Classifications extends Vue {
  @Prop() private classifications!: Classification[];
}
</script>
