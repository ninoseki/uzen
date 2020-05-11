<template>
  <div>
    <b-message type="is-warning">
      Importing data from urlscan.io might be lossy
    </b-message>

    <div class="box">
      <b-field>
        <b-input
          class="control is-expanded"
          placeholder="UUID"
          v-model="uuid"
        ></b-input>
        <p class="control">
          <b-button
            type="is-light"
            icon-pack="fas"
            icon-left="file-import"
            @click="import_from_urlscan"
            >Import from urlscan.io</b-button
          >
        </p>
      </b-field>
    </div>
  </div>
</template>

<script lang="ts">
import { Component, Mixin, Mixins } from "vue-mixin-decorator";
import { Prop } from "vue-property-decorator";
import axios, { AxiosError } from "axios";

import { ErrorData, Snapshot } from "@/types";

import { ErrorDialogMixin } from "@/components/mixins";

@Component
export default class Import extends Mixins<ErrorDialogMixin>(ErrorDialogMixin) {
  private uuid: string = "";

  async import_from_urlscan() {
    const loadingComponent = this.$buefy.loading.open({
      container: this.$el.firstElementChild,
    });

    try {
      const response = await axios.post<Snapshot>(`/api/import/${this.uuid}`);

      loadingComponent.close();

      const snapshot = response.data;

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
