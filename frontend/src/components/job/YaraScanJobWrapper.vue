<template>
  <div>
    <div class="box">
      <SimpleError
        :error="getJobStatusTask.last.error.response.data"
        v-if="getJobStatusTask.isError && getJobStatusTask.last !== undefined"
      ></SimpleError>
      <div
        v-else-if="
          getJobStatusTask.last !== undefined &&
          getJobStatusTask.last.value !== null &&
          getJobStatusTask.last.value.definition !== null &&
          getJobStatusTask.last.value.result === null
        "
      >
        <b-message type="is-info" has-icon>
          <p>Scanning snapshtos with YARA...</p>
          <div class="buttons">
            <b-button
              type="is-ghost"
              size="is-large"
              expanded
              loading
            ></b-button>
          </div>
        </b-message>
      </div>
      <div v-else>
        <b-message type="is-success" has-icon>
          <p>Scan finished!</p>
        </b-message>
      </div>

      <div
        class="mt-4"
        v-if="
          getJobStatusTask.last !== undefined &&
          getJobStatusTask.last.value !== null &&
          getJobStatusTask.last.value.definition !== null
        "
      >
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
      v-if="
        getJobStatusTask.last !== undefined &&
        getJobStatusTask.last.value !== null
      "
    ></YaraScanJob>
  </div>
</template>

<script lang="ts">
import { defineComponent, onMounted } from "@vue/composition-api";
import { useTitle } from "@vueuse/core";
import { useAsyncTask } from "vue-concurrency";

import { API } from "@/api";
import YaraScanJob from "@/components/job/YaraScanJob.vue";
import H3 from "@/components/ui/H3.vue";
import SimpleError from "@/components/ui/SimpleError.vue";
import YaraSource from "@/components/yara/Source.vue";
import { JOB_CHECK_INTERVAL } from "@/constants";
import { YaraScanJobStatus } from "@/types/job";

export default defineComponent({
  name: "YaraScanJobWrapper",
  components: {
    SimpleError,
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

    const getJobStatusTask = useAsyncTask<YaraScanJobStatus, []>(async () => {
      return await API.getYaraScanJobStatus(props.jobId);
    });

    const getJobStatus = async (): Promise<YaraScanJobStatus> => {
      return await getJobStatusTask.perform();
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
