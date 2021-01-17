<template>
  <div>
    <Loading v-if="importTask.isRunning"></Loading>
    <Error
      :error="importTask.last.error.response.data"
      v-else-if="importTask.isError && importTask.last !== undefined"
    ></Error>

    <b-message type="is-warning">
      Importing data from urlscan.io might be lossy
    </b-message>

    <div class="box">
      <b-field>
        <b-input
          class="control is-expanded"
          placeholder="UUID"
          v-model="uuid"
        ></b-input>
        <p class="control">
          <b-button
            type="is-light"
            icon-pack="fas"
            icon-left="file-import"
            @click="importFromUrlscan"
            >Import from urlscan.io</b-button
          >
        </p>
      </b-field>
    </div>
  </div>
</template>

<script lang="ts">
import { defineComponent, ref } from "@vue/composition-api";
import { useAsyncTask } from "vue-concurrency";

import { API } from "@/api";
import Error from "@/components/ui/Error.vue";
import Loading from "@/components/ui/Loading.vue";
import { Snapshot } from "@/types";

export default defineComponent({
  name: "Import",
  components: {
    Error,
    Loading,
  },
  setup(_, context) {
    const uuid = ref<string>("");

    const importTask = useAsyncTask<Snapshot, []>(async () => {
      return await API.importFromUrlscan(uuid.value);
    });

    const importFromUrlscan = async () => {
      const snapshot = await importTask.perform();
      context.root.$router.push({ path: `/snapshots/${snapshot.id}` });
    };

    return { uuid, importFromUrlscan, importTask };
  },
});
</script>
