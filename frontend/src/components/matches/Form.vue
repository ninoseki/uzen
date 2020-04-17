<template>
  <div>
    <div class="columns">
      <div class="column is-half">
        <b-field label="Rule ID">
          <b-input type="number" v-model="filters.rule_id"></b-input>
        </b-field>
      </div>
      <div class="column is-half">
        <b-field label="Snapshot ID">
          <b-input type="number" v-model="filters.snapshot_id"></b-input>
        </b-field>
      </div>
    </div>
    <div class="columns">
      <div class="column is-half">
        <b-field label="From">
          <b-datepicker
            :date-formatter="dateFormatter"
            placeholder="Click to select..."
            icon="calendar-today"
            v-model="filters.from_at"
          ></b-datepicker>
        </b-field>
      </div>
      <div class="column is-half">
        <b-field label="To">
          <b-datepicker
            :date-formatter="dateFormatter"
            placeholder="Click to select..."
            icon="calendar-today"
            v-model="filters.to_at"
          ></b-datepicker>
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
    rule_id: undefined,
    snapshot_id: undefined,
    from_at: undefined,
    to_at: undefined,
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
