<template>
  <div class="content">
    <b-message type="is-info" has-icon>
      Number of scripts: {{ scripts.length }}
    </b-message>

    <ul>
      <li v-for="script in scripts" :key="script.id">
        <router-link
          target="_blank"
          :to="{
            name: 'File',
            params: { hash: script.sha256 },
            query: { url: script.url },
          }"
          >{{ script.url }}
        </router-link>
        ({{ script.sha256 }})
      </li>
    </ul>
  </div>
</template>

<script lang="ts">
import { defineComponent, PropType } from "@vue/composition-api";

import { Script } from "@/types";

export default defineComponent({
  name: "Scripts",
  props: {
    scripts: {
      type: Array as PropType<Script[]>,
      required: true,
    },
  },
});
</script>
