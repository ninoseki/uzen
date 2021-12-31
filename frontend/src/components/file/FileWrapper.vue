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
import { defineComponent, onMounted } from "vue";
import { Ref } from "vue-concurrency/dist/vue3/src/utils/api";
import { useRoute, useRouter } from "vue-router";

import FileComponent from "@/components/file/File.vue";
import NA from "@/components/ui/NA.vue";
import Loading from "@/components/ui/SimpleLoading.vue";
import { generateGetFileTask } from "@/api-helper";

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

    const getFileTask = generateGetFileTask();

    onMounted(async () => {
      await getFileTask.perform(hash);
    });

    return { url, getFileTask };
  },
});
</script>
