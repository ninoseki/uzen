<template>
  <div>
    <div class="box">
      <b-field>
        <b-input class="control is-expanded" placeholder="URL" v-model="url"></b-input>
        <p class="control">
          <b-button type="is-light" @click="take">Take a snapshot</b-button>
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
  private url = "";
  private snapshot: Snapshot | undefined = undefined;

  async take() {
    const loadingComponent = this.$buefy.loading.open({
      container: this.$refs.element
    });

    try {
      const response = await axios.post<SnapshotData>("/api/snapshots/", {
        url: this.url
      });
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
