<template>
  <div></div>
</template>

<script lang="ts">
import { defineComponent, onMounted, onUnmounted } from "@vue/composition-api";
import { BLoadingComponent } from "buefy/types/components";

export default defineComponent({
  name: "Loading",
  setup(_, context) {
    let loadingComponent: BLoadingComponent | undefined = undefined;

    onMounted(() => {
      console.log(context.parent?.$el);
      loadingComponent = context.root.$buefy.loading.open({
        container: context.root.$parent,
      });
    });

    onUnmounted(() => {
      if (loadingComponent) {
        loadingComponent.close();
      }
    });
  },
});
</script>
