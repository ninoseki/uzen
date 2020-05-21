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
          <b-button
            type="is-light"
            icon-pack="fas"
            icon-left="camera"
            @click="take"
            >Take a snapshot</b-button
          >
          <b-button
            type="is-info"
            icon-pack="fas"
            icon-left="cogs"
            @click="showOptions = !showOptions"
            >Options</b-button
          >
        </p>
      </b-field>
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
  </div>
</template>

<script lang="ts">
import axios from "axios";
import { Component, Mixins } from "vue-mixin-decorator";

import { ErrorDialogMixin } from "@/components/mixins";
import Options from "@/components/snapshots/Options.vue";
import { ErrorData, Snapshot } from "@/types";

@Component({ components: { Options } })
export default class Form extends Mixins<ErrorDialogMixin>(ErrorDialogMixin) {
  private url = "";
  private showOptions = false;
  private snapshot: Snapshot | undefined = undefined;

  private acceptLanguage = "";
  private host = "";
  private ignoreHTTPSErrors = false;
  private referer = "";
  private timeout = 30000;
  private userAgent = "";

  async take() {
    const loadingComponent = this.$buefy.loading.open({
      container: this.$el.firstElementChild,
    });

    try {
      const response = await axios.post<Snapshot>("/api/snapshots/", {
        url: this.url,
        acceptLanguage:
          this.acceptLanguage === "" ? undefined : this.acceptLanguage,
        host: this.host === "" ? undefined : this.host,
        ignoreHttpsErrors: this.ignoreHTTPSErrors,
        referer: this.referer === "" ? undefined : this.referer,
        timeout: this.timeout,
        userAgent: this.userAgent === "" ? undefined : this.userAgent,
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
