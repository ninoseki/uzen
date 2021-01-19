<template>
  <div class="screenshot">
    <img :src="imageSource" alt="screenshot" />
  </div>
</template>

<script lang="ts">
import { computed, defineComponent } from "@vue/composition-api";

export default defineComponent({
  name: "Preview",
  props: {
    hostname: {
      type: String,
      required: true,
    },
  },
  setup(props) {
    const imageSource = computed((): string => {
      return `/api/screenshots/preview/${props.hostname}`;
    });

    return { imageSource };
  },
});
</script>

<style scoped>
.screenshot {
  min-height: 470px;
}
</style>
