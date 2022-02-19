<template>
  <div>
    <article class="message is-warning">
      <div class="message-body">Importing data from urlscan.io is lossy.</div>
    </article>

    <div class="box">
      <div class="field has-addons">
        <div class="control is-expanded">
          <input class="input" type="text" placeholder="UUID" v-model="uuid" />
        </div>
        <p class="control">
          <button class="button is-light" @click="importFromUrlscan">
            <span class="icon">
              <i class="fas fa-file-import"></i>
            </span>
            <span>Import from urlscan.io</span>
          </button>
        </p>
      </div>
    </div>

    <Loading v-if="importTask.isRunning"></Loading>
    <Error
      :error="importTask.last?.error.response.data"
      v-else-if="importTask.isError"
    ></Error>
  </div>
</template>

<script lang="ts">
import { defineComponent, ref } from "vue";
import { useRouter } from "vue-router";

import Error from "@/components/ui/SimpleError.vue";
import Loading from "@/components/ui/SimpleLoading.vue";
import { generateImportFromUrlscanTask } from "@/api-helper";

export default defineComponent({
  name: "ImportItem",
  components: {
    Error,
    Loading,
  },
  setup() {
    const router = useRouter();

    const uuid = ref<string>("");

    const importTask = generateImportFromUrlscanTask();

    const importFromUrlscan = async () => {
      const snapshot = await importTask.perform(uuid.value);
      router.push({ path: `/snapshots/${snapshot.id}` });
    };

    return { uuid, importTask, importFromUrlscan };
  },
});
</script>
