<template>
  <div>
    <b-field label="Device">
      <b-select
        v-model="deviceName"
        placeholder="Select a device to emulate"
        @input="onDeviceChange"
      >
        <option></option>
        <option
          v-for="device in devices"
          :value="device.name"
          :key="device.name"
        >
          {{ device.name }}
        </option>
      </b-select>
    </b-field>

    <b-field label="User agent">
      <b-input placeholder="User agent" v-model="userAgent"></b-input>
    </b-field>

    <b-field label="Referer">
      <b-input placeholder="Referer" v-model="referer"></b-input>
    </b-field>

    <b-field label="Accept language">
      <b-select
        v-model="acceptLanguage"
        placeholder="Select Accept Language HTTP header to use"
      >
        <option></option>
        <option v-for="langKey in languagKeys" :value="langKey" :key="langKey">
          {{ langKey }}
        </option>
      </b-select>
    </b-field>

    <b-field label="Other headers">
      <div class="columns" v-for="(header, index) in otherHeaders" :key="index">
        <div class="column is-half">
          <b-field label="Name">
            <b-input v-model="header.key"></b-input>
          </b-field>
        </div>
        <div class="column is-half">
          <b-field label="Value">
            <b-input v-model="header.value"></b-input>
          </b-field>
        </div>
      </div>
      <div class="column">
        <b-button class="is-pulled-right" @click="addEmptyHeader">Add</b-button>
      </div>
    </b-field>

    <div class="column">
      <hr />
    </div>

    <b-field
      label="Timeout (milliseconds)"
      message="Maximum navigation time in milliseconds, defaults to 30 seconds, pass 0 to disable timeout"
    >
      <b-input v-model="timeout" type="number"></b-input>
    </b-field>

    <b-field label="Wait until" message=" When to consider operation succeeded">
      <b-select v-model="waitUntil" required>
        <option value="load">load</option>
        <option value="domcontentloaded">domcontentloaded</option>
        <option value="networkidle">networkidle</option>
      </b-select>
    </b-field>

    <div class="column">
      <hr />
    </div>

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
import { Device, Header } from "@/types";
import { WaitUntilType } from "@/types";

export default defineComponent({
  name: "SnapshotOptions",
  setup(_, context) {
    const acceptLanguage = ref("");
    const ignoreHttpsErrors = ref(false);
    const enableHAR = ref(false);
    const referer = ref("");
    const timeout = ref(30000);
    const userAgent = ref(navigator.userAgent);
    const deviceName = ref("");
    const waitUntil = ref<WaitUntilType>("load");
    const otherHeaders = ref<Header[]>([]);
    const devices = ref<Device[]>([]);
    const languagKeys = Object.keys(languages);

    const addEmptyHeader = () => {
      otherHeaders.value.push({ key: "", value: "" });
    };

    const getDevicesTask = useAsyncTask<Device[], []>(async () => {
      return await API.getDevices();
    });

    const getDevices = async () => {
      devices.value = await getDevicesTask.perform();
    };

    const onDeviceChange = (newDeviceName: string) => {
      const newDevice = devices.value.find(
        (device) => device.name == newDeviceName
      );
      if (newDevice !== undefined) {
        userAgent.value = newDevice.descriptor.userAgent;
      }
    };

    onMounted(async () => {
      addEmptyHeader();

      await getDevices();
    });

    watch(
      [
        acceptLanguage,
        otherHeaders,
        ignoreHttpsErrors,
        referer,
        timeout,
        userAgent,
        enableHAR,
        deviceName,
        waitUntil,
      ],
      // eslint-disable-next-line no-unused-vars
      (_first, _second) => {
        context.emit("update:acceptLanguage", acceptLanguage.value);
        context.emit("update:otherHeaders", otherHeaders.value);
        context.emit("update:ignoreHttpsErrors", ignoreHttpsErrors.value);
        context.emit("update:enableHAR", enableHAR.value);
        context.emit("update:referer", referer.value);
        context.emit("update:userAgent", userAgent.value);
        context.emit("update:deviceName", deviceName.value);
        context.emit("update:waitUntil", waitUntil.value);

        if (typeof timeout.value === "string") {
          context.emit("update:timeout", parseInt(timeout.value));
        } else {
          context.emit("update:timeout", timeout.value);
        }
      }
    );

    return {
      acceptLanguage,
      otherHeaders,
      ignoreHttpsErrors,
      referer,
      timeout,
      userAgent,
      languages,
      languagKeys,
      enableHAR,
      deviceName,
      devices,
      waitUntil,
      onDeviceChange,
      addEmptyHeader,
    };
  },
});
</script>
