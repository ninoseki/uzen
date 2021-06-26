<template>
  <div>
    <div v-if="getTextTask.isRunning">Loading...</div>
    <div
      v-else-if="
        !getTextTask.isError && getTextTask.last && getTextTask.last.value
      "
    >
      <TextComponent
        :text="getTextTask.last.value"
        v-if="getTextTask.last.value"
      />
      <NA v-else></NA>
    </div>
    <NA v-else></NA>
  </div>
</template>

<script lang="ts">
import { defineComponent } from "@vue/composition-api";
import { useAsyncTask } from "vue-concurrency";

import { API } from "@/api";
import TextComponent from "@/components/text/Text.vue";
import NA from "@/components/ui/NA.vue";

export default defineComponent({
  name: "TextWrapper",
  props: {
    sha256: {
      type: String,
      required: true,
    },
  },
  components: {
    TextComponent,
    NA,
  },
  setup(props) {
    const getTextTask = useAsyncTask<string, []>(async () => {
      return await API.getText(props.sha256);
    });

    getTextTask.perform();

    return { getTextTask };
  },
});
</script>
