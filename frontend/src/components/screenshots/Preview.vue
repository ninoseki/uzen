<template>
  <div class="screenshot">
    <img v-if="loaded" :src="this.imageSource()" :alt="screenshot" />
  </div>
</template>

<script lang="ts">
import axios, { AxiosError } from "axios";
import { Component, Prop, Vue } from "vue-property-decorator";

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
    } catch (error) {
      this.failed = true;
    }
    this.loaded = true;
  }

  hasValidImageSource(): boolean {
    if (this.failed) {
      return false;
    }
    if (this.screenshot === undefined) {
      return false;
    }
    return this.screenshot.data !== "";
  }

  imageSource(): string {
    if (this.hasValidImageSource() && this.screenshot !== undefined) {
      return `data:Image/png;base64,${this.screenshot.data}`;
    }
    return `${process.env.BASE_URL}images/not-found.jpg`;
  }
}
</script>

<style scoped>
.screenshot {
  min-height: 470px;
}
</style>
