<template>
  <div>
    <Loading v-if="getHTMLTask.isRunning"></Loading>
    <div v-else-if="!getHTMLTask.isError && getHTMLTask.last?.value">
      <HTMLComponent
        :html="getHTMLTask.last.value.content"
        :sha256="getHTMLTask.last.value.sha256"
        v-if="getHTMLTask.last.value.content"
      />
      <NA v-else></NA>
    </div>
    <NA v-else></NA>
  </div>
</template>

<script lang="ts">
import { defineComponent, onMounted } from "vue";

import HTMLComponent from "@/components/html/HTML.vue";
import NA from "@/components/ui/NA.vue";
import Loading from "@/components/ui/SimpleLoading.vue";
import { generateGetHTMLTask } from "@/api-helper";

export default defineComponent({
  name: "HTMLWrapper",
  props: {
    sha256: {
      type: String,
      required: true,
    },
  },
  components: {
    HTMLComponent,
    NA,
    Loading,
  },
  setup(props) {
    const getHTMLTask = generateGetHTMLTask();

    onMounted(async () => {
      await getHTMLTask.perform(props.sha256);
    });

    return { getHTMLTask };
  },
});
</script>
