<template>
  <div>
    <div class="columns">
      <div class="column is-half">
        <div class="field">
          <label class="label">Rule ID</label>
          <div class="control">
            <input class="input" type="text" v-model="filters.ruleId" />
          </div>
        </div>
      </div>
      <div class="column is-half">
        <div class="field">
          <label class="label">Snapshot ID</label>
          <div class="control">
            <input class="input" type="text" v-model="filters.snapshotId" />
          </div>
        </div>
      </div>
    </div>
    <div class="columns">
      <div class="column is-half">
        <div class="field">
          <label class="label">From</label>
          <div class="control">
            <Datepicker v-model="filters.fromAt" />
          </div>
        </div>
      </div>
      <div class="column is-half">
        <div class="field">
          <label class="label">To</label>
          <div class="control">
            <Datepicker v-model="filters.toAt" />
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script lang="ts">
import { defineComponent, reactive } from "vue";
import Datepicker from "@vuepic/vue-datepicker";

import { MatchFilters } from "@/types";
import { normalizeFilterValue } from "@/utils/form";

export default defineComponent({
  name: "MatchesForm",
  props: {
    ruleId: String,
    snapshotId: String,
  },
  components: {
    Datepicker,
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

    return { filters, filtersParams };
  },
});
</script>
