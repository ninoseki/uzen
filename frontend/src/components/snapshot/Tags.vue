<template>
  <div class="tags is-inline-block" v-if="tags.length > 0">
    <div
      :class="tagSize"
      class="tag is-white is-light"
      v-for="tag in tags"
      :key="tag.name"
    >
      <router-link
        :to="{
          name: 'Snapshots',
          query: { tag: tag.name },
        }"
        >{{ tag.name }}
      </router-link>
    </div>
  </div>
</template>

<script lang="ts">
import { defineComponent, PropType } from "vue";

import { Tag } from "@/types";

export default defineComponent({
  name: "Tags",
  props: {
    tags: {
      type: Array as PropType<Tag[]>,
      required: true,
    },
    tagSize: {
      type: String,
      required: false,
    },
  },
});
</script>
