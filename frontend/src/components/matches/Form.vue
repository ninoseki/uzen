<template>
  <div>
    <div class="columns">
      <div class="column is-half">
        <b-field label="Rule ID">
          <b-input v-model="filters.ruleId"></b-input>
        </b-field>
      </div>
      <div class="column is-half">
        <b-field label="Snapshot ID">
          <b-input v-model="filters.snapshotId"></b-input>
        </b-field>
      </div>
    </div>
    <div class="columns">
      <div class="column is-half">
        <b-field label="From">
          <b-datetimepicker
            placeholder="Click to select..."
            icon="calendar-today"
            v-model="filters.fromAt"
            :datetime-formatter="datetimeFormatter"
          ></b-datetimepicker>
        </b-field>
      </div>
      <div class="column is-half">
        <b-field label="To">
          <b-datetimepicker
            placeholder="Click to select..."
            icon="calendar-today"
            v-model="filters.toAt"
            :datetime-formatter="datetimeFormatter"
          ></b-datetimepicker>
        </b-field>
      </div>
    </div>
  </div>
</template>

<script lang="ts">
import { Component, Mixin, Mixins } from "vue-mixin-decorator";
import { Prop } from "vue-property-decorator";

import { MatchFilters } from "@/types";

import {
  SearchFormMixin,
  ErrorDialogMixin,
  SearchFormComponentMixin,
} from "@/components/mixins";

@Component
export default class SearchForm extends Mixins<SearchFormComponentMixin>(
  ErrorDialogMixin,
  SearchFormMixin
) {
  private filters: MatchFilters = {
    ruleId: undefined,
    snapshotId: undefined,
    fromAt: undefined,
    toAt: undefined,
  };

  filtersParams() {
    const obj: { [k: string]: any } = {};

    for (const key in this.filters) {
      if (this.filters[key] !== undefined) {
        const value = this.filters[key];
        obj[key] = this.normalizeFilterValue(value);
      }
    }
    return obj;
  }
}
</script>
