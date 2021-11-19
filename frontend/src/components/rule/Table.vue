<template>
  <div class="box table-container" v-if="rules.length > 0">
    <table class="table is-fullwidth">
      <thead>
        <tr>
          <th>Name</th>
          <th>Target</th>
          <th>Created at</th>
          <th>Updated at</th>
        </tr>
      </thead>
      <tbody>
        <tr v-for="rule in rules" :key="rule.id">
          <td>
            <router-link
              :to="{
                name: 'Rule',
                params: { id: rule.id },
              }"
            >
              {{ rule.name }}
            </router-link>
          </td>
          <td>
            {{ rule.target }}
          </td>
          <td>
            <DatetimeWithDiff v-bind:datetime="rule.createdAt" />
          </td>
          <td>
            <DatetimeWithDiff v-bind:datetime="rule.updatedAt" />
          </td>
        </tr>
      </tbody>
    </table>
  </div>
</template>

<script lang="ts">
import { defineComponent, PropType } from "vue";

import DatetimeWithDiff from "@/components/ui/DatetimeWithDiff.vue";
import { Rule } from "@/types";

export default defineComponent({
  name: "RulesTable",
  components: {
    DatetimeWithDiff,
  },
  props: {
    rules: {
      type: Array as PropType<Rule[]>,
      required: true,
    },
  },
});
</script>
