<template>
  <div class="screenshot">
    <div v-if="isLoading">
      <b-notification :closable="false">
        <b-loading :is-full-page="false" v-model="isLoading"> </b-loading>
      </b-notification>
    </div>
    <img
      class="loading"
      :src="imageSource"
      alt="Failed to load the image"
      @load="onLoaded"
      @error="onLoaded"
    />
  </div>
</template>

<script lang="ts">
import { computed, defineComponent, ref } from "@vue/composition-api";

export default defineComponent({
  name: "Preview",
  props: {
    hostname: {
      type: String,
      required: true,
    },
  },

  setup(props) {
    const isLoading = ref(true);

    const onLoaded = () => {
      isLoading.value = false;
    };

    const imageSource = computed((): string => {
      return `/api/screenshots/preview/${props.hostname}`;
    });

    return { imageSource, isLoading, onLoaded };
  },
});
</script>

<style scoped>
.screenshot {
  min-height: 470px;
}

.notification {
  min-height: 350px;
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
