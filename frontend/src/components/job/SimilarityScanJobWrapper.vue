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
          <p>Scanning snapshtos...</p>
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
        <div class="table-container">
          <table class="table">
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
      v-if="
        getJobStatusTask.last !== undefined &&
        getJobStatusTask.last.value !== null
      "
    ></SimilarityScanJob>
  </div>
</template>

<script lang="ts">
import { defineComponent, onMounted } from "@vue/composition-api";
import { useTitle } from "@vueuse/core";
import { sha256 } from "js-sha256";
import { useAsyncTask } from "vue-concurrency";

import { API } from "@/api";
import SimilarityScanJob from "@/components/job/SimilarityScanJob.vue";
import DatetimeWithDiff from "@/components/ui/DatetimeWithDiff.vue";
import SimpleError from "@/components/ui/SimpleError.vue";
import { JOB_CHECK_INTERVAL } from "@/constants";
import { SimilarityScanJobStatus } from "@/types/job";

export default defineComponent({
  name: "SimilarityScanJobWrapper",
  components: {
    SimpleError,
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
