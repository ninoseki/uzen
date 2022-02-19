<template>
  <div class="screenshot">
    <img :src="imageSource" alt="screenshot" ref="screenshot" />
  </div>
</template>

<script lang="ts">
import { computed, defineComponent } from "vue";

export default defineComponent({
  name: "ScreenshotItem",
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

<style scoped>
.screenshot {
  text-align: center;
}

.screenshot img {
  border: 1px solid #aaa;
  border-radius: 5px;
  box-shadow: 5px 5px 5px #eee;
  max-height: 420px;
  object-fit: cover;
  object-position: top;
  overflow: hidden;
}
</style>
