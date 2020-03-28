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
      <Options
        v-if="showOptions"
        v-bind:acceptLanguage.sync="acceptLanguage"
        v-bind:ignoreHTTPSErrors.sync="ignoreHTTPSErrors"
        v-bind:timeout.sync="timeout"
        v-bind:userAgent.sync="userAgent"
      />
    </div>
  </div>
</template>

<script lang="ts">
import { Component, Prop, Vue } from "vue-property-decorator";
import axios, { AxiosError } from "axios";

import { ErrorData, Snapshot } from "@/types";

import Options from "@/components/snapshots/Options.vue";

@Component({ components: { Options } })
export default class Form extends Vue {
  private url = "";
  private showOptions = false;
  private userAgent = "";
  private acceptLanguage = "";
  private timeout = 30000;
  private ignoreHTTPSErrors = false;
  private snapshot: Snapshot | undefined = undefined;

  async take() {
    const loadingComponent = this.$buefy.loading.open({
      container: this.$refs.element
    });

    try {
      const response = await axios.post<Snapshot>("/api/snapshots/", {
        url: this.url,
        user_agent: this.userAgent === "" ? undefined : this.userAgent,
        accept_language:
          this.acceptLanguage === "" ? undefined : this.acceptLanguage,
        timeout: this.timeout,
        ignore_https_errors: this.ignoreHTTPSErrors
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
