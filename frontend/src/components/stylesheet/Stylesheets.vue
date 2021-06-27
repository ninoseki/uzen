<template>
  <div class="content">
    <b-message type="is-info" has-icon>
      Number of stylesheets: {{ stylesheets.length }}
    </b-message>
    <ul>
      <li v-for="stylesheet in stylesheets" :key="stylesheet.id">
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
import { defineComponent, PropType } from "@vue/composition-api";

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
