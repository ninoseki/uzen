<template>
  <div class="box">
    <SimpleError
      :error="getJobStatusTask.last.error.response.data"
      v-if="getJobStatusTask.isError && getJobStatusTask.last !== undefined"
    ></SimpleError>
    <div v-else>
      <b-message type="is-info" has-icon>
        <p>Taking a snapshot...</p>
        <div class="buttons">
          <b-button type="is-ghost" size="is-large" expanded loading></b-button>
        </div>
      </b-message>
    </div>
    <SnapshotJob
      :jobStatus="getJobStatusTask.last.value"
      v-if="
        getJobStatusTask.last !== undefined &&
        getJobStatusTask.last.value !== null
      "
    ></SnapshotJob>
  </div>
</template>

<script lang="ts">
import { defineComponent, onMounted } from "@vue/composition-api";
import { useTitle } from "@vueuse/core";
import { useAsyncTask } from "vue-concurrency";

import { API } from "@/api";
import SnapshotJob from "@/components/job/SnapshotJob.vue";
import SimpleError from "@/components/ui/SimpleError.vue";
import { SnapshotJobStatus } from "@/types";

export default defineComponent({
  name: "SnapshotJobWrapper",
  components: {
    SimpleError,
    SnapshotJob,
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
      }, 3000);
    });

    return {
      getJobStatusTask,
    };
  },
});
</script>
