<template>
  <div>
    <Loading v-if="getFileTask.isRunning"></Loading>
    <div v-else-if="!getFileTask.isError && getFileTask.last?.value">
      <FileComponent :file="getFileTask.last.value" :url="url" />
    </div>
    <NA v-else></NA>
  </div>
</template>

<script lang="ts">
import { useRouteQuery } from "@vueuse/router";
import { defineComponent } from "vue";
import { useAsyncTask } from "vue-concurrency";
import { Ref } from "vue-concurrency/dist/vue3/src/utils/api";
import { useRoute, useRouter } from "vue-router";

import { API } from "@/api";
import FileComponent from "@/components/file/File.vue";
import NA from "@/components/ui/NA.vue";
import Loading from "@/components/ui/SimpleLoading.vue";
import { File } from "@/types";

export default defineComponent({
  name: "FileWrapper",
  components: {
    Loading,
    FileComponent,
    NA,
  },
  setup() {
    const route = useRoute();
    const router = useRouter();
    const options = { route, router };

    const hash = route.params.hash as string;
    const url = useRouteQuery("url", undefined, options) as Ref<
      string | undefined
    >;

    const getFileTask = useAsyncTask<File, []>(async () => {
      return await API.getFile(hash);
    });

    getFileTask.perform();

    return { url, getFileTask };
  },
});
</script>
