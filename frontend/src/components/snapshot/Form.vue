<template>
  <div>
    <Loading v-if="takeSnapshotTask.isRunning"></Loading>
    <Error
      :error="takeSnapshotTask.last.error.response.data"
      v-else-if="
        takeSnapshotTask.isError && takeSnapshotTask.last !== undefined
      "
    ></Error>

    <div class="box">
      <b-field>
        <b-input
          class="control is-expanded"
          placeholder="URL"
          v-model="url"
        ></b-input>
        <p class="control">
          <b-button
            type="is-light"
            icon-pack="fas"
            icon-left="camera"
            @click="takeSnapshot"
            >Take a snapshot</b-button
          >
          <b-button
            type="is-info"
            icon-pack="fas"
            icon-left="cogs"
            @click="showOptions = !showOptions"
            >Options</b-button
          >
        </p>
      </b-field>
      <Options
        v-if="showOptions"
        :acceptLanguage.sync="acceptLanguage"
        :otherHeaders.sync="otherHeaders"
        :ignoreHttpsErrors.sync="ignoreHttpsErrors"
        :enableHAR.sync="enableHar"
        :referer.sync="referer"
        :timeout.sync="timeout"
        :userAgent.sync="userAgent"
        :deviceName.sync="deviceName"
        :waitUntil.sync="waitUntil"
      />
    </div>
  </div>
</template>

<script lang="ts">
import { defineComponent, ref } from "@vue/composition-api";
import { useAsyncTask } from "vue-concurrency";

import { API } from "@/api";
import Options from "@/components/snapshot/Options.vue";
import Error from "@/components/ui/Error.vue";
import Loading from "@/components/ui/Loading.vue";
import { CreateSnapshotPayload, Header, Headers, Snapshot } from "@/types";
import { WaitUntilType } from "@/types";

export default defineComponent({
  name: "SnapshotForm",
  components: {
    Error,
    Loading,
    Options,
  },
  setup(_, context) {
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

    const takeSnapshotTask = useAsyncTask<Snapshot, []>(async () => {
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

      return await API.takeSnapshot(payload);
    });

    const takeSnapshot = async () => {
      const snapshot = await takeSnapshotTask.perform();
      context.root.$router.push({ path: `/snapshots/${snapshot.id}` });
    };

    return {
      takeSnapshot,
      takeSnapshotTask,
      url,
      showOptions,
      acceptLanguage,
      userAgent,
      ignoreHttpsErrors,
      referer,
      timeout,
      enableHar,
      deviceName,
      waitUntil,
      otherHeaders,
    };
  },
});
</script>
