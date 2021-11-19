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
            <p>Scanning snapshtos...</p>
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
        <div class="table-container">
          <table class="table is-completely-borderless">
            <tbody>
              <tr>
                <th>HTML hash (sha256)</th>
                <td>
                  {{
                    sha256(getJobStatusTask.last.value.definition.payload.html)
                  }}
                </td>
              </tr>
              <tr>
                <th>Hostname to exclude</th>
                <td>
                  {{
                    getJobStatusTask.last.value.definition.payload
                      .excludeHostname || "N/A"
                  }}
                </td>
              </tr>
              <tr>
                <th>IP address to exclude</th>
                <td>
                  {{
                    getJobStatusTask.last.value.definition.payload
                      .excludeIPAddress || "N/A"
                  }}
                </td>
              </tr>
              <tr>
                <th>Enqueue time</th>
                <td>
                  <DatetimeWithDiff
                    :datetime="
                      getJobStatusTask.last.value.definition.enqueueTime
                    "
                  ></DatetimeWithDiff>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>

    <SimilarityScanJob
      :jobStatus="getJobStatusTask.last.value"
      v-if="getJobStatusTask.last?.value"
    ></SimilarityScanJob>
  </div>
</template>

<script lang="ts">
import { useTitle } from "@vueuse/core";
import { sha256 } from "js-sha256";
import { defineComponent, onMounted } from "vue";
import { useAsyncTask } from "vue-concurrency";

import { API } from "@/api";
import SimilarityScanJob from "@/components/job/SimilarityScanJob.vue";
import DatetimeWithDiff from "@/components/ui/DatetimeWithDiff.vue";
import Error from "@/components/ui/SimpleError.vue";
import Loading from "@/components/ui/SimpleLoading.vue";
import { JOB_CHECK_INTERVAL } from "@/constants";
import { SimilarityScanJobStatus } from "@/types/job";

export default defineComponent({
  name: "SimilarityScanJobWrapper",
  components: {
    Error,
    Loading,
    SimilarityScanJob,
    DatetimeWithDiff,
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

    const getJobStatusTask = useAsyncTask<SimilarityScanJobStatus, []>(
      async () => {
        return await API.getSimilarityScanJobStatus(props.jobId);
      }
    );

    const getJobStatus = async (): Promise<SimilarityScanJobStatus> => {
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
      sha256,
    };
  },
});
</script>
