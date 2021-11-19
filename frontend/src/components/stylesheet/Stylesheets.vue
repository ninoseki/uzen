<template>
  <div class="content">
    <article class="message is-info">
      <div class="message-body">
        Number of stylesheets: {{ stylesheets.length }}
      </div>
    </article>
    <ul>
      <li v-for="(stylesheet, index) in stylesheets" :key="index">
        <router-link
          target="_blank"
          :to="{
            name: 'File',
            params: { hash: stylesheet.sha256 },
            query: { url: stylesheet.url },
          }"
          >{{ stylesheet.url }}
        </router-link>
        ({{ stylesheet.sha256 }})
      </li>
    </ul>
  </div>
</template>

<script lang="ts">
import { defineComponent, PropType } from "vue";

import { Stylesheet } from "@/types";

export default defineComponent({
  name: "Stylesheets",
  props: {
    stylesheets: {
      type: Array as PropType<Stylesheet[]>,
      required: true,
    },
  },
});
</script>
