<template>
  <div>
    <div class="table-container" v-if="hasClassifications">
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
    <div v-else>
      <NA />
    </div>
  </div>
</template>

<script lang="ts">
import { Component, Prop, Vue } from "vue-property-decorator";

import NA from "@/components/ui/NA.vue";
import { Classification } from "@/types";

@Component({
  components: {
    NA,
  },
})
export default class Classifications extends Vue {
  @Prop() private classifications!: Classification[];

  get hasClassifications(): boolean {
    return this.classifications.length > 0;
  }
}
</script>
