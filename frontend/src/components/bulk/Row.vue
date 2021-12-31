<template>
  <div class="row">
    <div v-if="takeSnapshotTask.isRunning">
      <article class="message">
        <div class="message-body">Loading {{ url }}...</div>
      </article>
    </div>
    <div v-else-if="takeSnapshotTask.isError">
      <article class="message is-danger">
        <div class="message-body">
          Failed to take a snapshot of <strong>{{ url }}</strong>
        </div>
      </article>
    </div>
    <div v-else>
      <div v-if="takeSnapshotTask.last && takeSnapshotTask.last.value">
        <article class="message is-success">
          <div class="message-body">
            <p><strong>Submitted URL:</strong> {{ url }}</p>
            <p>
              <strong>Job ID:</strong>
              <router-link
                :to="{
                  name: 'SnapshotJob',
                  params: {
                    id: takeSnapshotTask.last.value.id,
                  },
                }"
              >
                {{ takeSnapshotTask.last.value.id }}
              </router-link>
            </p>
          </div>
        </article>
      </div>
    </div>
  </div>
</template>

<script lang="ts">
import { defineComponent, onMounted, PropType } from "vue";

import { CreateSnapshotPayload, Header, Headers, WaitUntilType } from "@/types";
import { generateTakeSnapshotTask } from "@/api-helper";

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
    waitUntil: {
      type: String as PropType<WaitUntilType>,
      required: true,
    },
    otherHeaders: {
      type: Array as PropType<Header[]>,
      required: true,
    },
  },
  setup(props) {
    const sleep = (): Promise<void> => {
      const timeout = 1000 * props.index;
      return new Promise((resolve) => setTimeout(resolve, timeout));
    };

    const takeSnapshotTask = generateTakeSnapshotTask();

    const takeSnapshot = async () => {
      await sleep();

      const headers: Headers = {};
      headers["User-Agent"] = props.userAgent;

      if (props.acceptLanguage !== "") {
        headers["Accept-Language"] = props.acceptLanguage;
      }
      if (props.referer !== "") {
        headers["Referer"] = props.referer;
      }

      props.otherHeaders.forEach((header) => {
        if (header.key !== "" && header.value !== "") {
          headers[header.key] = header.value;
        }
      });

      const payload: CreateSnapshotPayload = {
        url: props.url,
        enableHar: props.enableHar,
        timeout: props.timeout,
        ignoreHttpsErrors: props.ignoreHttpsErrors,
        waitUntil: props.waitUntil,
        deviceName: props.deviceName === "" ? undefined : props.deviceName,
        headers,
      };

      return await takeSnapshotTask.perform(payload);
    };

    onMounted(async () => {
      await takeSnapshot();
    });

    return { takeSnapshotTask };
  },
});
</script>

<style scoped>
.row {
  margin-top: 10px;
  margin-bottom: 10px;
}
</style>
