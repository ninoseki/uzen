<template>
  <div>
    <div v-if="getFileTask.isRunning">Loading...</div>
    <div
      v-else-if="
        !getFileTask.isError && getFileTask.last && getFileTask.last.value
      "
    >
      <FileComponent :file="getFileTask.last.value" :url="url" />
    </div>
    <NA v-else></NA>
  </div>
</template>

<script lang="ts">
import { defineComponent } from "@vue/composition-api";
import { useAsyncTask } from "vue-concurrency";

import { API } from "@/api";
import FileComponent from "@/components/file/File.vue";
import NA from "@/components/ui/NA.vue";
import { File } from "@/types";

export default defineComponent({
  name: "FileWrapper",
  components: {
    FileComponent,
    NA,
  },
  setup(props, { root }) {
    const hash = root.$route.params.hash;
    const url = root.$route.query.url as string | null;

    const getFileTask = useAsyncTask<File, []>(async () => {
      return await API.getFile(hash);
    });

    getFileTask.perform();

    return { getFileTask, url };
  },
});
</script>
