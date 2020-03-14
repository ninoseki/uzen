<template>
  <span>(total: {{ count }})</span>
</template>

<script lang="ts">
import { Component, Vue } from "vue-property-decorator";
import axios, { AxiosError } from "axios";

import { SnapshotCount } from "@/types";

@Component
export default class Counter extends Vue {
  private count: number = 0;

  async load() {
    try {
      const response = await axios.get<SnapshotCount>("/api/snapshots/count");
      const data = response.data;
      this.count = data.count;
    } catch (error) {
      this.count = 0;
    }
  }

  created() {
    this.load();
  }
}
</script>
