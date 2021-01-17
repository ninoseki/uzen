<template>
  <h2 class="is-size-4 has-text-weight-bold">
    <slot />
  </h2>
</template>

<script lang="ts">
import { defineComponent } from "@vue/composition-api";

export default defineComponent({
  name: "H2",
});
</script>

<style scoped>
h2 {
  padding-bottom: 10px;
  margin-bottom: 10px;
}
</style>
