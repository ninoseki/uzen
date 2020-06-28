<template>
  <div class="screenshot">
    <img :src="this.imageSource" :alt="screenshot" />
  </div>
</template>

<script lang="ts">
import { Component, Prop, Vue } from "vue-property-decorator";

@Component
export default class Preview extends Vue {
  @Prop() private hostname!: string;

  get imageSource(): string {
    return `/api/screenshots/preview/${this.hostname}?output_format=png`;
  }
}
</script>

<style scoped>
.screenshot {
  min-height: 470px;
}
</style>
