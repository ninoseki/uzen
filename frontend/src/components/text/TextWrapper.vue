<template>
  <div>
    <Loading v-if="getTextTask.isRunning"></Loading>
    <div v-else-if="!getTextTask.isError && getTextTask.last?.value">
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
import { defineComponent, onMounted } from "vue";

import TextComponent from "@/components/text/Text.vue";
import NA from "@/components/ui/NA.vue";
import Loading from "@/components/ui/SimpleLoading.vue";
import { generateGetTextTask } from "@/api-helper";

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
    Loading,
    NA,
  },
  setup(props) {
    const getTextTask = generateGetTextTask();

    onMounted(async () => {
      await getTextTask.perform(props.sha256);
    });

    return { getTextTask };
  },
});
</script>
