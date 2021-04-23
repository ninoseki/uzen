<template>
  <div class="box">
    <SimpleError
      :error="getJobStatusTask.last.error.response.data"
      v-if="getJobStatusTask.isError && getJobStatusTask.last !== undefined"
    ></SimpleError>
    <b-message type="is-info" has-icon v-else>
      <p>Taking a snapshot...</p>
      <b-progress class="mt-5"></b-progress>
    </b-message>
  </div>
</template>

<script lang="ts">
import { defineComponent, onMounted } from "@vue/composition-api";
import { useTitle } from "@vueuse/core";
import { useAsyncTask } from "vue-concurrency";

import { API } from "@/api";
import SimpleError from "@/components/ui/SimpleError.vue";
import { SnapshotJobStatus } from "@/types";

export default defineComponent({
  name: "JobWrapper",
  components: {
    SimpleError,
  },
  props: {
    jobId: {
      type: String,
      required: true,
    },
  },

  setup(props, context) {
    const updateTitle = (): void => {
      useTitle(`${props.jobId} - Uzen`);
    };

    const getJobStatusTask = useAsyncTask<SnapshotJobStatus, []>(async () => {
      return await API.getSnapshotJobStatus(props.jobId);
    });

    const getJobStatus = async (): Promise<SnapshotJobStatus> => {
      return await getJobStatusTask.perform();
    };

    onMounted(async () => {
      updateTitle();

      const refreshId = setInterval(async () => {
        try {
          const status = await getJobStatus();

          if (status.isRunning === false && status.result !== null) {
            clearInterval(refreshId);

            context.root.$router.push({
              path: `/snapshots/${status.result.snapshotId}`,
            });
          }
        } catch (error) {
          clearInterval(refreshId);
        }
      }, 1000);
    });

    return {
      getJobStatusTask,
    };
  },
});
</script>
