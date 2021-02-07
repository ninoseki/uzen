<template>
  <div>
    <b-taglist v-if="classifications.length > 0">
      <Tag
        v-for="classification in classifications"
        :key="classification.id"
        :classification="classification"
      ></Tag>
    </b-taglist>
    <div v-else>N/A</div>
  </div>
</template>

<script lang="ts">
import { defineComponent, PropType } from "@vue/composition-api";

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
