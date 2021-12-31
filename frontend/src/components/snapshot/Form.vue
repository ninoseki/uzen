<template>
  <div>
    <Loading v-if="takeSnapshotTask.isRunning"></Loading>
    <Error
      :error="takeSnapshotTask.last.error.response.data"
      v-else-if="takeSnapshotTask.isError && takeSnapshotTask.last"
    ></Error>

    <div class="box">
      <div class="field has-addons">
        <div class="control is-expanded">
          <input class="input" type="text" placeholder="URL" v-model="url" />
        </div>
        <p class="control">
          <button class="button is-light" @click="takeSnapshot">
            <span class="icon">
              <i class="fas fa-camera"></i>
            </span>
            <span>Take a snapshot</span>
          </button>
          <button class="button is-info" @click="showOptions = !showOptions">
            <span class="icon">
              <i class="fas fa-cogs"></i>
            </span>
            <span>Options</span>
          </button>
        </p>
      </div>

      <Status></Status>

      <Options
        v-if="showOptions"
        v-model:acceptLanguage="acceptLanguage"
        v-model:otherHeaders="otherHeaders"
        v-model:ignoreHttpsErrors="ignoreHttpsErrors"
        v-model:enableHAR="enableHar"
        v-model:referer="referer"
        v-model:timeout="timeout"
        v-model:userAgent="userAgent"
        v-model:deviceName="deviceName"
        v-model:waitUntil="waitUntil"
      />
    </div>
  </div>
</template>

<script lang="ts">
import { defineComponent, ref } from "vue";
import { useRouter } from "vue-router";

import Options from "@/components/snapshot/Options.vue";
import Status from "@/components/snapshot/Status.vue";
import Error from "@/components/ui/SimpleError.vue";
import Loading from "@/components/ui/SimpleLoading.vue";
import { CreateSnapshotPayload, Header, Headers } from "@/types";
import { WaitUntilType } from "@/types";
import { generateTakeSnapshotTask } from "@/api-helper";

export default defineComponent({
  name: "SnapshotForm",
  components: {
    Error,
    Loading,
    Options,
    Status,
  },
  setup() {
    const router = useRouter();

    const url = ref("");
    const showOptions = ref(false);
    const acceptLanguage = ref("");
    const ignoreHttpsErrors = ref(false);
    const enableHar = ref(false);
    const referer = ref("");
    const timeout = ref(30000);
    const userAgent = ref(navigator.userAgent);
    const deviceName = ref("");
    const waitUntil = ref<WaitUntilType>("load");
    const otherHeaders = ref<Header[]>([]);

    const takeSnapshotTask = generateTakeSnapshotTask();

    const takeSnapshot = async () => {
      const headers: Headers = {
        "User-Agent": userAgent.value,
      };
      if (acceptLanguage.value !== "") {
        headers["Accept-Language"] = acceptLanguage.value;
      }
      if (referer.value !== "") {
        headers["Referer"] = referer.value;
      }

      otherHeaders.value.forEach((header) => {
        if (header.key !== "" && header.value !== "") {
          headers[header.key] = header.value;
        }
      });

      const payload: CreateSnapshotPayload = {
        url: url.value,
        enableHar: enableHar.value,
        timeout: timeout.value,
        ignoreHttpsErrors: ignoreHttpsErrors.value,
        waitUntil: waitUntil.value,
        deviceName: deviceName.value === "" ? undefined : deviceName.value,
        headers,
      };

      const job = await takeSnapshotTask.perform(payload);

      router.push({ path: `/jobs/snapshots/${job.id}` });
    };

    return {
      acceptLanguage,
      deviceName,
      enableHar,
      ignoreHttpsErrors,
      otherHeaders,
      referer,
      showOptions,
      takeSnapshotTask,
      timeout,
      url,
      userAgent,
      waitUntil,
      takeSnapshot,
    };
  },
});
</script>
