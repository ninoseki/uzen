<template>
  <div>
    <div class="columns">
      <div class="column is-half">
        <b-field label="Name">
          <b-input v-model="filters.name"></b-input>
        </b-field>
      </div>
      <div class="column is-half">
        <b-field label="Target">
          <b-input placeholder="body" v-model="filters.target"></b-input>
        </b-field>
      </div>
    </div>
    <div class="columns">
      <div class="column">
        <b-field label="Source">
          <b-input v-model="filters.source"></b-input>
        </b-field>
      </div>
    </div>
  </div>
</template>

<script lang="ts">
import { Component, Prop, Vue } from "vue-property-decorator";

import { RuleFilters, TargetTypes } from "@/types";

@Component
export default class SearchForm extends Vue {
  @Prop() private name: string | undefined;
  @Prop() private target: TargetTypes | undefined;
  @Prop() private source: string | undefined;

  get filters(): RuleFilters {
    return {
      name: this.name,
      target: this.target,
      source: this.source,
    };
  }

  filtersParams() {
    const obj: { [k: string]: string | number | undefined } = {};

    for (const key in this.filters) {
      if (this.filters[key] !== undefined) {
        const value = this.filters[key];
        obj[key] = value;
      }
    }
    return obj;
  }
}
</script>
