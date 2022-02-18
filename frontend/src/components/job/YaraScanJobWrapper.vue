<template>
  <div>
    <div class="box">
      <Error
        :error="getJobStatusTask.last.error.response.data"
        v-if="getJobStatusTask.isError && getJobStatusTask.last"
      ></Error>
      <div
        v-else-if="
          getJobStatusTask.last === undefined ||
          (getJobStatusTask.last.value?.definition !== null &&
            getJobStatusTask.last.value?.result === null)
        "
      >
        <article class="message is-info">
          <div class="message-body">
            <p>Scanning snapshots with YARA...</p>
            <Loading></Loading>
          </div>
        </article>
      </div>
      <div v-else>
        <article class="message is-success">
          <div class="message-body">
            <p>Scan finished!</p>
          </div>
        </article>
      </div>

      <div class="mt-4" v-if="getJobStatusTask.last?.value?.definition">
        <H3
          >Source (Target:
          {{ getJobStatusTask.last.value.definition.payload.target }})</H3
        >
        <YaraSource
          :source="getJobStatusTask.last.value.definition.payload.source"
        ></YaraSource>
      </div>
    </div>

    <YaraScanJob
      :jobStatus="getJobStatusTask.last.value"
      v-if="getJobStatusTask.last?.value"
    ></YaraScanJob>
  </div>
</template>

<script lang="ts">
import { useTitle } from "@vueuse/core";
import { defineComponent, onMounted } from "vue";

import YaraScanJob from "@/components/job/YaraScanJob.vue";
import H3 from "@/components/ui/H3.vue";
import Error from "@/components/ui/SimpleError.vue";
import Loading from "@/components/ui/SimpleLoading.vue";
import YaraSource from "@/components/yara/Source.vue";
import { JOB_CHECK_INTERVAL } from "@/constants";
import { YaraScanJobStatus } from "@/types/job";
import { generateGetYaraScanJobStatusTask } from "@/api-helper";

export default defineComponent({
  name: "YaraScanJobWrapper",
  components: {
    Error,
    Loading,
    YaraScanJob,
    YaraSource,
    H3,
  },
  props: {
    jobId: {
      type: String,
      required: true,
    },
  },

  setup(props) {
    const updateTitle = (): void => {
      useTitle(`${props.jobId} - Uzen`);
    };

    const getJobStatusTask = generateGetYaraScanJobStatusTask();

    const getJobStatus = async (): Promise<YaraScanJobStatus> => {
      return await getJobStatusTask.perform(props.jobId);
    };

    onMounted(async () => {
      updateTitle();

      const refreshId = setInterval(async () => {
        try {
          const status = await getJobStatus();

          if (status.isRunning === false && status.result !== null) {
            clearInterval(refreshId);
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
