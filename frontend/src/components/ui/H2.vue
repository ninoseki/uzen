<template>
  <h2 class="is-size-4 has-text-weight-bold">
    <slot />
  </h2>
</template>

<script lang="ts">
import { Component, Vue } from "vue-property-decorator";

@Component
export default class H2 extends Vue {}
</script>

<style scoped>
h2 {
  padding-bottom: 10px;
  margin-bottom: 10px;
}
</style>
