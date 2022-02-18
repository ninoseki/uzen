<template>
  <div>
    <div class="field">
      <label class="label">Name</label>
      <div class="control">
        <input class="input" type="text" v-model="filters.name" />
      </div>
    </div>
    <div class="field">
      <label class="label">Target</label>
      <div class="control">
        <div class="select">
          <select placeholder="Target for a YARA rule" v-model="filters.target">
            <option></option>
            <option v-for="t in targets" :value="t" :key="t">
              {{ t }}
            </option>
          </select>
        </div>
      </div>
    </div>
    <div class="field">
      <label class="label">Source</label>
      <div class="control">
        <input class="input" type="text" v-model="filters.source" />
      </div>
    </div>
  </div>
</template>

<script lang="ts">
import { defineComponent, PropType, reactive } from "vue";

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
    const targets: TargetTypes[] = ["html", "whois", "certificate", "script"];

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

    return { filters, targets, filtersParams };
  },
});
</script>
