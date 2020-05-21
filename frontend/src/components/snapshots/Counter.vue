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
import { Component, Vue, Prop } from "vue-property-decorator";
import axios, { AxiosError } from "axios";

import { SnapshotSearchResults, ErrorData } from "@/types";

@Component
export default class Counter extends Vue {
  @Prop() private hostname: string | undefined;
  @Prop() private ipAddress: string | undefined;

  private totalCount: number = 0;

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
    }
  }
}
</script>
