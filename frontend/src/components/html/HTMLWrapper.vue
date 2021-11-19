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
import { defineComponent } from "vue";
import { useAsyncTask } from "vue-concurrency";

import { API } from "@/api";
import HTMLComponent from "@/components/html/HTML.vue";
import NA from "@/components/ui/NA.vue";
import Loading from "@/components/ui/SimpleLoading.vue";
import { HTML } from "@/types";

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
    const getHTMLTask = useAsyncTask<HTML, []>(async () => {
      return await API.getHTML(props.sha256);
    });

    getHTMLTask.perform();

    return { getHTMLTask };
  },
});
</script>
