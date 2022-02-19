<template>
  <a :href="link.href(hostname)" class="link" target="_blank">
    <img :src="link.favicon" alt="favicon" />
    <span>{{ link.name }}</span>
  </a>
</template>

<script lang="ts">
import { defineComponent, PropType } from "vue";

import { Link } from "@/types";

export default defineComponent({
  name: "LinkItem",
  props: {
    hostname: {
      type: String,
      required: true,
    },
    link: {
      type: Object as PropType<Link>,
      required: true,
    },
  },
});
</script>

<style scoped>
.link img {
  margin-right: 5px;
}
</style>
