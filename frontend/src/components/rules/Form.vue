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
import { defineComponent, PropType, reactive } from "@vue/composition-api";

import { RuleFilters, TargetTypes } from "@/types";

export default defineComponent({
  name: "RuleSearchForm",
  props: {
    name: String,
    target: {
      type: String as PropType<TargetTypes>,
    },
    source: String,
  },
  setup(props) {
    const filters = reactive<RuleFilters>({
      name: props.name,
      target: props.target,
      source: props.source,
    });

    const filtersParams = () => {
      const obj: { [k: string]: string | number | undefined } = {};

      for (const key in filters) {
        if (filters[key] !== undefined) {
          const value = filters[key];
          obj[key] = value;
        }
      }
      return obj;
    };

    return { filters, filtersParams };
  },
});
</script>
