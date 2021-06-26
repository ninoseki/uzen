<template>
  <pre>{{ text }} </pre>
</template>

<script lang="ts">
import { defineComponent } from "@vue/composition-api";

export default defineComponent({
  name: "TextComponent",
  props: {
    text: {
      type: String,
      required: true,
    },
  },
});
</script>
