<template>
  <a v-bind:href="link.href(hostname, ipAddress)" class="link" target="_blank">
    <img v-bind:src="link.favicon" alt="favicon" />
    <span>{{ link.name }}</span>
  </a>
</template>

<script lang="ts">
import { Component, Vue, Prop } from "vue-property-decorator";

import { Snapshot, Link } from "@/types";

@Component
export default class LinkComponent extends Vue {
  @Prop() private hostname!: string;
  @Prop() private ipAddress!: string;
  @Prop() private link!: Link;
}
</script>

<style scoped>
.link img {
  margin-right: 5px;
}
</style>
