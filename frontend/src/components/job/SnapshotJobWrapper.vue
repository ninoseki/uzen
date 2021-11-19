<template>
  <div class="box">
    <Error
      :error="getJobStatusTask.last.error.response.data"
      v-if="getJobStatusTask.isError && getJobStatusTask.last"
    ></Error>
    <div v-else>
      <article class="message is-info">
        <div class="message-body">
          <p>Taking a snapshot...</p>
          <Loading></Loading>
        </div>
      </article>
    </div>
    <SnapshotJob
      :jobStatus="getJobStatusTask.last.value"
      v-if="getJobStatusTask.last?.value"
    ></SnapshotJob>
  </div>
</template>

<script lang="ts">
import { useTitle } from "@vueuse/core";
import { defineComponent, onMounted } from "vue";
import { useAsyncTask } from "vue-concurrency";
import { useRouter } from "vue-router";

import { API } from "@/api";
import SnapshotJob from "@/components/job/SnapshotJob.vue";
import Error from "@/components/ui/SimpleError.vue";
import Loading from "@/components/ui/SimpleLoading.vue";
import { JOB_CHECK_INTERVAL } from "@/constants";
import { SnapshotJobStatus } from "@/types";

export default defineComponent({
  name: "SnapshotJobWrapper",
  components: {
    Error,
    Loading,
    SnapshotJob,
  },
  props: {
    jobId: {
      type: String,
      required: true,
    },
  },

  setup(props) {
    const router = useRouter();

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
            router.push({
              path: `/snapshots/${status.result.snapshotId}`,
            });
          }
        } catch (error) {
          clearInterval(refreshId);
        }
      }, JOB_CHECK_INTERVAL);
    });

    return {
      getJobStatusTask,
    };
  },
});
</script>
