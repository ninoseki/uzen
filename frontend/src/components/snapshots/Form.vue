<template>
  <div>
    <div class="box">
      <b-field>
        <b-input
          class="control is-expanded"
          placeholder="URL"
          v-model="url"
        ></b-input>
        <p class="control">
          <b-button type="is-light" @click="take">Take a snapshot</b-button>
          <b-button
            type="is-info"
            icon-left="fas fa-cogs"
            @click="showOptions = !showOptions"
            >Options</b-button
          >
        </p>
      </b-field>
      <div id="options" v-if="showOptions">
        <b-field label="User Agent">
          <b-input
            placeholder="Specific user agent to use"
            v-model="userAgent"
          ></b-input>
        </b-field>

        <b-field label="Accept Language">
          <b-select
            v-model="acceptLanguage"
            placeholder="Select Accept Language HTTP header to use"
          >
            <option
              v-for="langKey in languagKeys"
              :value="langKey"
              :key="langKey"
            >
              {{ langKey }} / {{ languages[langKey] }}
            </option>
          </b-select>
        </b-field>

        <b-field label="Timeout (milliseconds)">
          <b-input
            v-model="timeout"
            type="number"
            placeholder="Maximum navigation time in milliseconds, defaults to 30 seconds, pass 0 to disable timeout"
          ></b-input>
        </b-field>
        <b-field label="Ignore HTTPS errors">
          <b-checkbox v-model="ignoreHTTPSErrors"></b-checkbox>
        </b-field>
      </div>
    </div>
  </div>
</template>

<script lang="ts">
import { Component, Prop, Vue } from "vue-property-decorator";
import axios, { AxiosError } from "axios";

import { ErrorData, Snapshot } from "@/types";
import { languages } from "@/languages";

@Component
export default class Form extends Vue {
  private url = "";
  private showOptions = false;
  private userAgent = "";
  private acceptLanguage = "";
  private timeout = 30000;
  private ignoreHTTPSErrors = false;
  private snapshot: Snapshot | undefined = undefined;
  private languages = languages;
  private languagKeys = Object.keys(languages);

  async take() {
    const loadingComponent = this.$buefy.loading.open({
      container: this.$refs.element,
    });

    try {
      const response = await axios.post<Snapshot>("/api/snapshots/", {
        url: this.url,
        user_agent: this.userAgent === "" ? undefined : this.userAgent,
        accept_language:
          this.acceptLanguage === "" ? undefined : this.acceptLanguage,
        timeout: this.timeout,
        ignore_https_errors: this.ignoreHTTPSErrors,
      });
      const snapshot = response.data;

      loadingComponent.close();

      // redirect to the details page
      this.$router.push({ path: `/snapshots/${snapshot.id}` });
    } catch (error) {
      loadingComponent.close();

      const data = error.response.data as ErrorData;
      alert(data.detail);
    }
  }
}
</script>
