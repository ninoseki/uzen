<template>
  <div class="row">
    <div v-if="takeSnapshotTask.isRunning">
      <b-message>Loading {{ url }}...</b-message>
    </div>
    <div v-else-if="takeSnapshotTask.isError">
      <b-message type="is-danger" has-icon>
        Failed to take a snapshot of <strong>{{ url }}</strong
        >.
      </b-message>
    </div>
    <div v-else>
      <div v-if="takeSnapshotTask.last && takeSnapshotTask.last.value">
        <b-message type="is-success" has-icon>
          <router-link
            :to="{
              name: 'Snapshot',
              params: {
                id: takeSnapshotTask.last.value.id,
              },
            }"
          >
            {{ truncate(takeSnapshotTask.last.value.url) }}
          </router-link>
          <p><strong>Submitted URL:</strong> {{ url }}</p>
          <p><strong>ID:</strong> {{ takeSnapshotTask.last.value.id }}</p>
        </b-message>
      </div>
    </div>
  </div>
</template>

<script lang="ts">
import { defineComponent } from "@vue/composition-api";
import { useAsyncTask } from "vue-concurrency";

import { API } from "@/api";
import { CreateSnapshotPayload, Headers, Snapshot } from "@/types";
import { truncate } from "@/utils/truncate";

export default defineComponent({
  name: "BulkRow",
  props: {
    url: {
      type: String,
      required: true,
    },
    index: {
      type: Number,
      required: true,
    },
    acceptLanguage: {
      type: String,
      required: true,
    },
    host: {
      type: String,
      required: true,
    },
    ignoreHttpsErrors: {
      type: Boolean,
      required: true,
    },
    enableHar: {
      type: Boolean,
      required: true,
    },
    referer: {
      type: String,
      required: true,
    },
    timeout: {
      type: Number,
      required: true,
    },
    userAgent: {
      type: String,
      required: true,
    },
    deviceName: {
      type: String,
      required: true,
    },
  },
  setup(props) {
    const sleep = (): Promise<void> => {
      const timeout = 1000 * props.index;
      return new Promise((resolve) => setTimeout(resolve, timeout));
    };

    const takeSnapshotTask = useAsyncTask<Snapshot, []>(async () => {
      await sleep();

      const headers: Headers = {};
      headers["User-Agent"] = props.userAgent;

      if (props.acceptLanguage !== "") {
        headers["Accept-Language"] = props.acceptLanguage;
      }
      if (props.host !== "") {
        headers["Host"] = props.host;
      }
      if (props.referer !== "") {
        headers["Referer"] = props.referer;
      }

      const payload: CreateSnapshotPayload = {
        url: props.url,
        enableHar: props.enableHar,
        timeout: props.timeout,
        ignoreHttpsErrors: props.ignoreHttpsErrors,
        deviceName: props.deviceName === "" ? undefined : props.deviceName,
        headers,
      };

      return await API.takeSnapshot(payload);
    });

    takeSnapshotTask.perform();

    return { takeSnapshotTask, truncate };
  },
});
</script>

<style scoped>
.row {
  margin-top: 10px;
  margin-bottom: 10px;
}
</style>
