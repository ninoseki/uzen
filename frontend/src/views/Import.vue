<template>
  <div>
    <div class="box">
      <b-field>
        <b-input
          class="control is-expanded"
          placeholder="UUID"
          v-model="uuid"
        ></b-input>
        <p class="control">
          <b-button type="is-light" @click="import_from_urlscan"
            >Import from urlscan.io</b-button
          >
        </p>
      </b-field>
    </div>

    <b-message type="is-warning">
      Importing data from urlscan.io might be lossy
    </b-message>

    <div>
      <SnapshotComponebnt v-if="hasSnapshot()" v-bind:snapshot="snapshot" />
    </div>
  </div>
</template>

<script lang="ts">
import { Component, Mixin, Mixins } from "vue-mixin-decorator";
import { Prop } from "vue-property-decorator";
import axios, { AxiosError } from "axios";

import { ErrorData, Snapshot } from "@/types";

import SnapshotComponebnt from "@/components/snapshots/Snapshot.vue";

import { ErrorDialogMixin } from "@/components/mixins";

@Component({
  components: {
    SnapshotComponebnt,
  },
})
export default class SnapshotForm extends Mixins<ErrorDialogMixin>(
  ErrorDialogMixin
) {
  private uuid: string = "";
  private snapshot: Snapshot | undefined = undefined;

  async import_from_urlscan() {
    const loadingComponent = this.$buefy.loading.open({
      container: this.$refs.element,
    });

    try {
      const response = await axios.post<Snapshot>(`/api/import/${this.uuid}`);

      loadingComponent.close();

      this.snapshot = response.data;

      this.$forceUpdate();
    } catch (error) {
      loadingComponent.close();

      const data = error.response.data as ErrorData;
      this.alertError(data);
    }
  }

  hasSnapshot(): boolean {
    return this.snapshot !== undefined;
  }
}
</script>
