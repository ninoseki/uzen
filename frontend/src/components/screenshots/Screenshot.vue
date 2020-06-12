<template>
  <img :src="this.imageSource()" :alt="screenshot" ref="screenshot" />
</template>

<script lang="ts">
import { Component, Prop, Vue } from "vue-property-decorator";

@Component
export default class ScreenshotComponent extends Vue {
  @Prop() private snapshot_id!: string;

  imageSource(): string {
    return `/api/screenshots/${this.snapshot_id}?output_format=png`;
  }
}
</script>
