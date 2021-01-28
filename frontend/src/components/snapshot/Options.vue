<template>
  <div>
    <b-field label="Device">
      <b-select v-model="deviceName" placeholder="Select a device to emulate">
        <option></option>
        <option v-for="name in deviceNames" :key="name">
          {{ name }}
        </option>
      </b-select>
    </b-field>

    <b-field
      label="User Agent"
      message="It will be overridden if you set a device"
    >
      <b-input placeholder="User agent" v-model="userAgent"></b-input>
    </b-field>

    <b-field label="Referer">
      <b-input placeholder="Referer" v-model="referer"></b-input>
    </b-field>

    <b-field label="Accept Language">
      <b-select
        v-model="acceptLanguage"
        placeholder="Select Accept Language HTTP header to use"
      >
        <option></option>
        <option v-for="langKey in languagKeys" :key="langKey">
          {{ langKey }} / {{ languages[langKey] }}
        </option>
      </b-select>
    </b-field>

    <b-field
      label="Host"
      message="Just send a GET request to the URL and record a response if this option is set"
    >
      <b-input placeholder="Host" v-model="host"></b-input>
    </b-field>

    <b-field
      label="Timeout (milliseconds)"
      message="Maximum navigation time in milliseconds, defaults to 30 seconds, pass 0 to disable timeout"
    >
      <b-input v-model="timeout" type="number"></b-input>
    </b-field>

    <b-field label="Ignore HTTPS errors">
      <b-checkbox v-model="ignoreHttpsErrors"></b-checkbox>
    </b-field>

    <b-field label="Enable HAR">
      <b-checkbox v-model="enableHAR"></b-checkbox>
    </b-field>
  </div>
</template>

<script lang="ts">
import { defineComponent, onMounted, ref, watch } from "@vue/composition-api";
import { useAsyncTask } from "vue-concurrency";

import { API } from "@/api";
import { languages } from "@/languages";
import { Device } from "@/types";

export default defineComponent({
  name: "SnapshotOptions",
  setup(_, context) {
    const acceptLanguage = ref("");
    const host = ref("");
    const ignoreHttpsErrors = ref(false);
    const enableHAR = ref(false);
    const referer = ref("");
    const timeout = ref(30000);
    const userAgent = ref(navigator.userAgent);
    const deviceName = ref("");

    const deviceNames = ref<string[]>([]);
    const languagKeys = Object.keys(languages);

    const getDevicesTask = useAsyncTask<Device[], []>(async () => {
      return await API.getDevices();
    });

    const getDevices = async () => {
      const devices = await getDevicesTask.perform();
      deviceNames.value = devices.map((device) => device.name);
    };

    onMounted(async () => {
      await getDevices();
    });

    watch(
      [
        acceptLanguage,
        host,
        ignoreHttpsErrors,
        referer,
        timeout,
        userAgent,
        enableHAR,
        deviceName,
      ],
      // eslint-disable-next-line no-unused-vars
      (_first, _second) => {
        context.emit("update:acceptLanguage", acceptLanguage.value);
        context.emit("update:host", host.value);
        context.emit("update:ignoreHttpsErrors", ignoreHttpsErrors.value);
        context.emit("update:enableHAR", enableHAR.value);
        context.emit("update:referer", referer.value);
        context.emit("update:userAgent", userAgent.value);
        context.emit("update:deviceName", deviceName.value);

        if (typeof timeout.value === "string") {
          context.emit("update:timeout", parseInt(timeout.value));
        } else {
          context.emit("update:timeout", timeout.value);
        }
      }
    );

    return {
      acceptLanguage,
      host,
      ignoreHttpsErrors,
      referer,
      timeout,
      userAgent,
      languages,
      languagKeys,
      enableHAR,
      deviceName,
      deviceNames,
    };
  },
});
</script>
