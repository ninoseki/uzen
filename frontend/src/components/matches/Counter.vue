<template>
  <span>
    (
    <router-link
      :to="{
        name: 'Matches',
        query: { ruleId: ruleId },
      }"
      >{{ this.totalCount }} in total
    </router-link>
    )</span
  >
</template>

<script lang="ts">
import axios from "axios";
import { Component, Prop, Vue } from "vue-property-decorator";

import { ErrorData, MatchSearchResults } from "@/types";

@Component
export default class Counter extends Vue {
  @Prop() private ruleId: string | undefined;

  private totalCount = 0;

  created() {
    this.load();
  }

  async load() {
    const params = {
      size: 0,
      ruleId: this.ruleId,
    };

    try {
      const response = await axios.get<MatchSearchResults>(
        "/api/matches/search",
        {
          params: params,
        }
      );

      this.totalCount = response.data.total;
    } catch (error) {
      const data = error.response.data as ErrorData;
      // eslint-disable-next-line no-console
      console.error(data);
    }
  }
}
</script>
