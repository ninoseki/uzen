<template>
  <h4 class="is-size-6 has-text-weight-bold">
    <slot />
  </h4>
</template>

<script lang="ts">
import { defineComponent } from "vue";

export default defineComponent({
  name: "H4Item",
});
</script>

<style scoped>
h4 {
  padding-bottom: 5px;
  margin-bottom: 5px;
  border-bottom: 1px solid lightgray;
}
</style>
