<template>
  <img :src="imageSource" alt="screenshot" ref="screenshot" />
</template>

<script lang="ts">
import { computed, defineComponent } from "@vue/composition-api";

export default defineComponent({
  name: "Screenshot",
  props: {
    snapshotId: {
      type: String,
      required: true,
    },
  },
  setup(props) {
    const imageSource = computed((): string => {
      return `/api/screenshots/${props.snapshotId}`;
    });

    return { imageSource };
  },
});
</script>
