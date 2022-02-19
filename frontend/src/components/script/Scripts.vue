<template>
  <div class="content">
    <article class="message is-info">
      <div class="message-body">Number of scripts: {{ scripts.length }}</div>
    </article>

    <ul>
      <li v-for="(script, index) in scripts" :key="index">
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
import { defineComponent, PropType } from "vue";

import { Script } from "@/types";

export default defineComponent({
  name: "ScriptsItem",
  props: {
    scripts: {
      type: Array as PropType<Script[]>,
      required: true,
    },
  },
});
</script>
