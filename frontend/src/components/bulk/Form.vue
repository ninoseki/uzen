<template>
  <div>
    <div class="box">
      <div class="field">
        <label class="label"> URL </label>
        <p class="control">
          <textarea
            class="textarea is-expanded"
            placeholder="http://example.com"
            type="textarea"
            v-model="urlText"
          />
        </p>
      </div>

      <div class="buttons is-centered mt-5">
        <button class="button is-light" @click="bulkSubmit">
          <span class="icon">
            <i class="fas fa-search"></i>
          </span>
          <span>Submit</span>
        </button>
        <button class="button is-info" @click="showOptions = !showOptions">
          <span class="icon">
            <i class="fas fa-cogs"></i>
          </span>
          <span>Options</span>
        </button>
      </div>

      <Options
        v-if="showOptions"
        v-model:acceptLanguage="acceptLanguage"
        v-model:otherHeaders="otherHeaders"
        v-model:ignoreHttpSErrors="ignoreHttpsErrors"
        v-model:referer="referer"
        v-model:timeout="timeout"
        v-model:userAgent="userAgent"
        v-model:deviceName="deviceName"
        v-model:waitUntil="waitUntil"
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
        :otherHeaders="otherHeaders"
        :ignoreHttpsErrors="ignoreHttpsErrors"
        :referer="referer"
        :timeout="timeout"
        :userAgent="userAgent"
        :deviceName="deviceName"
        :waitUntil="waitUntil"
      />
    </div>
  </div>
</template>

<script lang="ts">
import { defineComponent, ref } from "vue";

import Row from "@/components/bulk/Row.vue";
import Options from "@/components/snapshot/Options.vue";
import { Header, WaitUntilType } from "@/types";

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
    const ignoreHttpsErrors = ref(false);
    const enableHar = ref(false);
    const referer = ref("");
    const timeout = ref(30000);
    const userAgent = ref("");
    const deviceName = ref("");
    const otherHeaders = ref<Header[]>([]);
    const waitUntil = ref<WaitUntilType>("load");

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
      acceptLanguage,
      deviceName,
      enableHar,
      ignoreHttpsErrors,
      otherHeaders,
      referer,
      showOptions,
      timeout,
      urls,
      urlText,
      userAgent,
      waitUntil,
      bulkSubmit,
      hasURLs,
    };
  },
});
</script>
