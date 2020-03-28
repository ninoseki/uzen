<template>
  <div>
    <b-field label="User Agent">
      <b-input
        placeholder="Specific user agent to use"
        v-model="_userAgent"
      ></b-input>
    </b-field>

    <b-field label="Accept Language">
      <b-select
        v-model="_acceptLanguage"
        placeholder="Select Accept Language HTTP header to use"
      >
        <option v-for="langKey in languagKeys" :value="langKey" :key="langKey">
          {{ langKey }} / {{ languages[langKey] }}
        </option>
      </b-select>
    </b-field>

    <b-field label="Timeout (milliseconds)">
      <b-input
        v-model="_timeout"
        type="number"
        placeholder="Maximum navigation time in milliseconds, defaults to 30 seconds, pass 0 to disable timeout"
      ></b-input>
    </b-field>
    <b-field label="Ignore HTTPS errors">
      <b-checkbox v-model="_ignoreHTTPSErrors"></b-checkbox>
    </b-field>
  </div>
</template>

<script lang="ts">
import { Component, Prop, Vue } from "vue-property-decorator";

import { ErrorData, Snapshot } from "@/types";
import { languages } from "@/languages";

@Component
export default class Options extends Vue {
  private userAgent = "";
  private acceptLanguage = "";
  private timeout = 30000;
  private ignoreHTTPSErrors = false;
  private languages = languages;
  private languagKeys = Object.keys(languages);

  get _userAgent() {
    return this.userAgent;
  }

  set _userAgent(value) {
    this.$emit("update:userAgent", value);
  }

  get _acceptLanguage() {
    return this.acceptLanguage;
  }

  set _acceptLanguage(value) {
    this.$emit("update:acceptLanguage", value);
  }

  get _timeout() {
    return this.timeout;
  }

  set _timeout(value) {
    this.$emit("update:timeout", value);
  }

  get _ignoreHTTPSErrors() {
    return this.timeout;
  }

  set _ignoreHTTPSErrors(value) {
    this.$emit("update:ignoreHTTPSErrors", value);
  }
}
</script>
