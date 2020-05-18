<template>
  <img
    v-if="loaded"
    :src="this.imageSource()"
    :alt="screenshot"
    ref="screenshot"
  />
</template>

<script lang="ts">
import { Component, Prop, Vue } from "vue-property-decorator";
import axios, { AxiosError } from "axios";

import { Screenshot } from "@/types";

@Component
export default class Preview extends Vue {
  @Prop() private hostname!: string;

  private screenshot: Screenshot | undefined = undefined;
  private failed: boolean = false;
  private loaded: boolean = false;

  created() {
    this.load();
  }

  async load() {
    try {
      const response = await axios.get<Screenshot>(
        `/api/screenshots/preview/${this.hostname}`
      );
      this.screenshot = response.data;
      this.$forceUpdate();
    } catch (error) {
      this.failed = true;
    }
    this.loaded = true;
  }

  hasInvalidImageSource(): boolean {
    if (this.failed) {
      return true;
    }
    return this.screenshot?.data === "";
  }

  imageSource(): string {
    if (this.hasInvalidImageSource()) {
      return `${process.env.BASE_URL}images/not-found.jpg`;
    }

    if (this.screenshot !== undefined) {
      return `data:Image/png;base64,${this.screenshot.data}`;
    }
    return "";
  }
}
</script>
