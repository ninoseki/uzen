<template>
  <div>
    <b-field label="User Agent">
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
        <option v-for="langKey in languagKeys" :value="langKey" :key="langKey">
          {{ langKey }} / {{ languages[langKey] }}
        </option>
      </b-select>
    </b-field>

    <b-field label="Host">
      <b-input placeholder="Host" v-model="host"></b-input>
    </b-field>

    <b-field label="Timeout (milliseconds)">
      <b-input
        v-model="timeout"
        type="number"
        placeholder="Maximum navigation time in milliseconds, defaults to 30 seconds, pass 0 to disable timeout"
      ></b-input>
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
import { defineComponent, ref, watch } from "@vue/composition-api";

import { languages } from "@/languages";

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

    const languagKeys = Object.keys(languages);

    watch(
      [
        acceptLanguage,
        host,
        ignoreHttpsErrors,
        referer,
        timeout,
        userAgent,
        enableHAR,
      ],
      // eslint-disable-next-line no-unused-vars
      (_first, _second) => {
        context.emit("update:acceptLanguage", acceptLanguage.value);
        context.emit("update:host", host.value);
        context.emit("update:ignoreHttpsErrors", ignoreHttpsErrors.value);
        context.emit("update:enableHAR", enableHAR.value);
        context.emit("update:referer", referer.value);
        context.emit("update:userAgent", userAgent.value);

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
    };
  },
});
</script>
