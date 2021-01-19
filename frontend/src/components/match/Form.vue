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
import { defineComponent, reactive } from "@vue/composition-api";

import { MatchFilters } from "@/types";
import { datetimeFormatter, normalizeFilterValue } from "@/utils/form";

export default defineComponent({
  name: "MatchesForm",
  props: {
    ruleId: String,
    snapshotId: String,
  },
  setup(props) {
    const filters = reactive<MatchFilters>({
      ruleId: props.ruleId,
      snapshotId: props.snapshotId,
      fromAt: undefined,
      toAt: undefined,
    });

    const filtersParams = () => {
      const obj: { [k: string]: string | number | undefined } = {};

      for (const key in filters) {
        if (filters[key] !== undefined) {
          const value = filters[key];
          obj[key] = normalizeFilterValue(value);
        }
      }
      return obj;
    };

    return { filters, filtersParams, datetimeFormatter };
  },
});
</script>
