<template>
  <div>
    <div class="box">
      <b-field>
        <b-input class="control is-expanded" placeholder="UUID" v-model="uuid"></b-input>
        <p class="control">
          <b-button type="is-light" @click="import_from_urlscan">Import from urlscan.io</b-button>
        </p>
      </b-field>
    </div>

    <div>
      <SnapshotDetail v-if="hasSnapshot()" v-bind:data="snapshot" />
    </div>
  </div>
</template>

<script lang="ts">
import { Component, Prop, Vue } from "vue-property-decorator";
import axios, { AxiosError } from "axios";

import { ErrorData, Snapshot, SnapshotData } from "@/types";

import SnapshotDetail from "@/components/SnapshotDetail.vue";

@Component({
  components: {
    SnapshotDetail
  }
})
export default class SnapshotForm extends Vue {
  private uuid: string = "";
  private snapshot: Snapshot | undefined = undefined;

  async import_from_urlscan() {
    const loadingComponent = this.$buefy.loading.open({
      container: this.$refs.element
    });

    try {
      const response = await axios.post<SnapshotData>(
        `/api/import/${this.uuid}`
      );
      const data = response.data;

      loadingComponent.close();

      this.snapshot = data.snapshot;
    } catch (error) {
      loadingComponent.close();

      const data = error.response.data as ErrorData;
      alert(data.detail);
    }
  }

  hasSnapshot(): boolean {
    return this.snapshot !== undefined;
  }
}
</script>
