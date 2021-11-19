<template>
  <div>
    <div class="field">
      <label class="label">Device</label>
      <div class="control">
        <div class="select">
          <select v-model="deviceName" placeholder="Select a device to emulate">
            <option></option>
            <option
              v-for="device in devices"
              :value="device.name"
              :key="device.name"
            >
              {{ device.name }}
            </option>
          </select>
        </div>
      </div>
    </div>

    <div class="field">
      <label class="label">User agent</label>
      <div class="control">
        <input
          class="input"
          type="text"
          placeholder="User agent"
          v-model="userAgent"
        />
      </div>
    </div>

    <div class="field">
      <label class="label">Referer</label>
      <div class="control">
        <input
          class="input"
          type="text"
          placeholder="Referer"
          v-model="referer"
        />
      </div>
    </div>

    <div class="field">
      <label class="label">Accept language</label>
      <div class="control">
        <div class="select">
          <select
            v-model="acceptLanguage"
            placeholder="Select Accept Language HTTP header to use"
          >
            <option></option>
            <option
              v-for="langKey in languagKeys"
              :value="langKey"
              :key="langKey"
            >
              {{ langKey }}
            </option>
          </select>
        </div>
      </div>
    </div>

    <div class="field">
      <label class="label">Other headers</label>

      <div class="columns" v-for="(header, index) in otherHeaders" :key="index">
        <div class="column is-half">
          <div class="field">
            <label class="label">Name</label>
            <div class="control">
              <input class="input" type="text" v-model="header.key" />
            </div>
          </div>
        </div>
        <div class="column is-half">
          <div class="field">
            <label class="label">Value</label>
            <div class="control">
              <input class="input" type="text" v-model="header.value" />
            </div>
          </div>
        </div>
      </div>
      <div class="column">
        <button class="button is-pulled-right" @click="addEmptyHeader">
          Add
        </button>
      </div>
    </div>

    <div class="column">
      <hr />
    </div>

    <div class="field">
      <label class="label">Timeout (milliseconds)</label>
      <div class="control">
        <input class="input" type="number" v-model="timeout" />
      </div>
      <p class="help">
        Maximum navigation time in milliseconds, defaults to 30 seconds, pass 0
        to disable timeout
      </p>
    </div>

    <div class="field">
      <label class="label">Wait until</label>
      <div class="control">
        <div class="select">
          <select v-model="waitUntil" required>
            <option value="load">load</option>
            <option value="domcontentloaded">domcontentloaded</option>
            <option value="networkidle">networkidle</option>
          </select>
        </div>
      </div>
      <p class="help">When to consider operation succeeded</p>
    </div>

    <div class="column">
      <hr />
    </div>

    <div class="field">
      <label class="label">Ignore HTTPS errors</label>
      <div class="control">
        <label class="checkbox">
          <input type="checkbox" v-model="ignoreHttpsErrors" />
        </label>
      </div>
    </div>

    <div class="field">
      <label class="label">Eanble HAR</label>
      <div class="control">
        <label class="checkbox">
          <input type="checkbox" v-model="enableHAR" />
        </label>
      </div>
    </div>
  </div>
</template>

<script lang="ts">
import { defineComponent, onMounted, ref, watchEffect } from "vue";
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

    watchEffect(() => {
      onDeviceChange(deviceName.value);

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
    });

    return {
      acceptLanguage,
      deviceName,
      devices,
      enableHAR,
      ignoreHttpsErrors,
      languages,
      languagKeys,
      otherHeaders,
      referer,
      timeout,
      userAgent,
      waitUntil,
      addEmptyHeader,
      onDeviceChange,
    };
  },
});
</script>
