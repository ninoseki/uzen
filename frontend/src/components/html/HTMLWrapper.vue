<template>
  <div>
    <div
      v-if="!getHTMLTask.isError && getHTMLTask.last && getHTMLTask.last.value"
    >
      <HTMLComponent
        :html="getHTMLTask.last.value.content"
        v-if="getHTMLTask.last.value.content"
      />
    </div>
    <NA v-else></NA>
  </div>
</template>

<script lang="ts">
import { defineComponent } from "@vue/composition-api";
import { useAsyncTask } from "vue-concurrency";

import { API } from "@/api";
import HTMLComponent from "@/components/html/HTML.vue";
import NA from "@/components/ui/NA.vue";
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
