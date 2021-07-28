<template>
  <b-taglist class="is-inline-block" v-if="tags.length > 0">
    <b-tag
      :size="tagSize"
      class="is-white is-light"
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
    </b-tag>
  </b-taglist>
</template>

<script lang="ts">
import { defineComponent, PropType } from "@vue/composition-api";

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
