<template>
  <span>
    (
    <router-link
      :to="{
        name: 'Snapshots',
        query: { hostname: hostname, ipAddress: ipAddress },
      }"
      >{{ this.totalCount }} in total
    </router-link>
    )</span
  >
</template>

<script lang="ts">
import axios from "axios";
import { Component, Prop, Vue } from "vue-property-decorator";

import { ErrorData, SnapshotSearchResults } from "@/types";

@Component
export default class Counter extends Vue {
  @Prop() private hostname: string | undefined;
  @Prop() private ipAddress: string | undefined;

  private totalCount = 0;

  created() {
    this.load();
  }

  async load() {
    const params = {
      size: 0,
      hostname: this.hostname,
      ipAddress: this.ipAddress,
    };

    try {
      const response = await axios.get<SnapshotSearchResults>(
        "/api/snapshots/search",
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
