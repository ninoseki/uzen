<template>
  <img :src="this.imageSource()" :alt="screenshot" ref="screenshot" />
</template>

<script lang="ts">
import axios from "axios";
import { Component, Prop, Vue } from "vue-property-decorator";

import { Screenshot } from "@/types";

@Component
export default class ScreenshotComponent extends Vue {
  @Prop() private screenshot!: Screenshot;
  @Prop() private snapshot_id!: string;

  private _screenshot: Screenshot | undefined = undefined;
  private failed = false;

  created() {
    if (this.screenshot !== undefined && this.screenshot !== null) {
      this._screenshot = this.screenshot;
    } else {
      this.load();
    }
  }

  async load() {
    try {
      const response = await axios.get<Screenshot>(
        `/api/screenshots/${this.snapshot_id}`
      );
      this._screenshot = response.data;
      this.$forceUpdate();
    } catch (error) {
      this.failed = true;
    }
  }

  hasValidImageSource(): boolean {
    if (this.failed) {
      return false;
    }
    if (this._screenshot === undefined) {
      return false;
    }
    return this._screenshot.data !== "";
  }

  imageSource(): string {
    if (this.hasValidImageSource() && this._screenshot !== undefined) {
      return `data:Image/png;base64,${this._screenshot.data}`;
    }
    return `${process.env.BASE_URL}images/not-found.jpg`;
  }
}
</script>
