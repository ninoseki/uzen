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
        :acceptLanguage.sync="acceptLanguage"
        :host.sync="host"
        :ignoreHttpSErrors.sync="ignoreHttpsErrors"
        :referer.sync="referer"
        :timeout.sync="timeout"
        :userAgent.sync="userAgent"
        :deviceName.sync="deviceName"
      />
    </div>

    <div class="box" v-if="hasURLs()">
      <Row
        v-for="(url, index) in urls"
        :key="url + index"
        :url="url"
        :index="index"
        :acceptLanguage="acceptLanguage"
        :enableHar="enableHar"
        :host="host"
        :ignoreHttpsErrors="ignoreHttpsErrors"
        :referer="referer"
        :timeout="timeout"
        :userAgent="userAgent"
        :deviceName="deviceName"
      />
    </div>
  </div>
</template>

<script lang="ts">
import { defineComponent, ref } from "@vue/composition-api";

import Row from "@/components/bulk/Row.vue";
import Options from "@/components/snapshot/Options.vue";

export default defineComponent({
  name: "Form",
  components: {
    Options,
    Row,
  },
  setup() {
    const urlText = ref("");
    const showOptions = ref(false);
    const acceptLanguage = ref("");
    const host = ref("");
    const ignoreHttpsErrors = ref(false);
    const enableHar = ref(false);
    const referer = ref("");
    const timeout = ref(30000);
    const userAgent = ref("");
    const deviceName = ref("");

    const urls = ref<string[]>([]);

    const bulkSubmit = () => {
      if (urlText.value.trim() !== "") {
        urls.value = urlText.value.split("\n");
      }
    };

    const hasURLs = (): boolean => {
      return urls.value.length > 0;
    };

    return {
      urlText,
      showOptions,
      acceptLanguage,
      host,
      ignoreHttpsErrors,
      referer,
      timeout,
      userAgent,
      bulkSubmit,
      hasURLs,
      urls,
      enableHar,
      deviceName,
    };
  },
});
</script>
