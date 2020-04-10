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
        v-bind:referer.sync="referer"
        v-bind:timeout.sync="timeout"
        v-bind:userAgent.sync="userAgent"
      />
    </div>
  </div>
</template>

<script lang="ts">
import { Component, Mixin, Mixins } from "vue-mixin-decorator";
import { Prop } from "vue-property-decorator";
import axios, { AxiosError } from "axios";

import { ErrorData, Snapshot } from "@/types";

import Options from "@/components/snapshots/Options.vue";

import { ErrorDialogMixin } from "@/components/mixins";

@Component({ components: { Options } })
export default class Form extends Mixins<ErrorDialogMixin>(ErrorDialogMixin) {
  private url = "";
  private showOptions = false;
  private acceptLanguage = "";
  private ignoreHTTPSErrors = false;
  private referer = "";
  private timeout = 30000;
  private userAgent = "";
  private snapshot: Snapshot | undefined = undefined;

  async take() {
    const loadingComponent = this.$buefy.loading.open({
      container: this.$refs.element,
    });

    try {
      const response = await axios.post<Snapshot>("/api/snapshots/", {
        url: this.url,
        accept_language:
          this.acceptLanguage === "" ? undefined : this.acceptLanguage,
        ignore_https_errors: this.ignoreHTTPSErrors,
        referer: this.referer === "" ? undefined : this.referer,
        timeout: this.timeout,
        user_agent: this.userAgent === "" ? undefined : this.userAgent,
      });
      const snapshot = response.data;

      loadingComponent.close();

      // redirect to the details page
      this.$router.push({ path: `/snapshots/${snapshot.id}` });
    } catch (error) {
      loadingComponent.close();

      const data = error.response.data as ErrorData;
      this.alertError(data);
    }
  }
}
</script>
