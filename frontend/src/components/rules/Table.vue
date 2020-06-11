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

        <b-table-column field="createdAt" label="Created at">
          <DatetimeWithDiff v-bind:datetime="props.row.createdAt" />
        </b-table-column>

        <b-table-column field="updatedAt" label="Updated at">
          <DatetimeWithDiff v-bind:datetime="props.row.updatedAt" />
        </b-table-column>
      </template>
    </b-table>
  </div>
</template>

<script lang="ts">
import { Component, Prop, Vue } from "vue-property-decorator";

import DatetimeWithDiff from "@/components/ui/DatetimeWithDiff.vue";
import { Rule } from "@/types";

@Component({
  components: {
    DatetimeWithDiff,
  },
})
export default class Table extends Vue {
  @Prop() private rules!: Rule[];

  hasRules(): boolean {
    return this.rules.length > 0;
  }
}
</script>
