<template>
  <div>
    <div class="tags" v-if="classifications.length > 0">
      <Tag
        v-for="(classification, index) in classifications"
        :key="index"
        :classification="classification"
      ></Tag>
    </div>
    <div v-else>N/A</div>
  </div>
</template>

<script lang="ts">
import { defineComponent, PropType } from "vue";

import Tag from "@/components/classification/Tag.vue";
import { Classification } from "@/types";

export default defineComponent({
  name: "ClassificationButtons",
  components: {
    Tag,
  },
  props: {
    classifications: {
      type: Array as PropType<Classification[]>,
      required: true,
    },
  },
});
</script>
