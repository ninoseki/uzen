<template>
  <div>
    <div class="box">
      <b-field label="URL">
        <b-input
          class="control is-expanded"
          placeholder="http://example.com"
          type="textarea"
          v-model="urlText"
        ></b-input>
      </b-field>

      <br />

      <div class="buttons is-centered">
        <b-button
          type="is-light"
          icon-pack="fas"
          icon-left="search"
          @click="bulkSubmit"
          >Submit</b-button
        >
        <b-button
          type="is-info"
          icon-pack="fas"
          icon-left="cogs"
          @click="showOptions = !showOptions"
          >Options</b-button
        >
      </div>

      <Options
        v-if="showOptions"
        v-bind:acceptLanguage.sync="acceptLanguage"
        v-bind:host.sync="host"
        v-bind:ignoreHTTPSErrors.sync="ignoreHTTPSErrors"
        v-bind:referer.sync="referer"
        v-bind:timeout.sync="timeout"
        v-bind:userAgent.sync="userAgent"
      />
    </div>

    <div class="box" v-if="hasURLs()">
      <Row
        v-for="(url, index) in urls"
        :key="url + index"
        :url="url"
        :index="index"
        :acceptLanguage="acceptLanguage"
        :host="host"
        :ignoreHTTPSErrors="ignoreHTTPSErrors"
        :referer="referer"
        :timeout="timeout"
        :userAgent="userAgent"
      />
    </div>
  </div>
</template>

<script lang="ts">
import { Component, Vue } from "vue-property-decorator";

import Row from "@/components/bulk/Row.vue";
import Options from "@/components/snapshots/Options.vue";

@Component({ components: { Options, Row } })
export default class Form extends Vue {
  private urlText = "";
  private showOptions = false;

  private acceptLanguage = "";
  private host = "";
  private ignoreHTTPSErrors = false;
  private referer = "";
  private timeout = 30000;
  private userAgent = "";

  private urls: string[] = [];

  bulkSubmit() {
    this.urls = this.urlText.split("\n");
  }

  hasURLs(): boolean {
    return this.urls.length > 0;
  }
}
</script>
