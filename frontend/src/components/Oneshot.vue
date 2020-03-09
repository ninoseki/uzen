<template>
  <div>
    <div class="box">
      <b-field label="URL">
        <b-input
          class="control is-expanded"
          placeholder="http://example.com"
          v-model="url"
        ></b-input>
      </b-field>

      <BasicYaraForm v-bind:source.sync="source" v-bind:target.sync="target" />

      <br />
      <div class="has-text-centered">
        <b-button type="is-light" @click="scan">Scan</b-button>
      </div>
    </div>
    <div class="message">
      <b-message v-if="hasSnapshot()" :type="messageType()">
        {{ message() }}
      </b-message>
    </div>

    <div>
      <SnapshotDetail
        v-if="hasSnapshot()"
        v-bind:snapshot="snapshot"
        v-bind:propScripts="scripts"
      />
    </div>
  </div>
</template>

<script lang="ts">
import { Component, Prop, Vue } from "vue-property-decorator";
import axios, { AxiosError } from "axios";

import { ErrorData, Snapshot, Oneshot, TargetTypes, Script } from "@/types";

import SnapshotDetail from "@/components/SnapshotDetail.vue";
import BasicYaraForm from "@/components/BasicYaraForm.vue";

@Component({
  components: {
    BasicYaraForm,
    SnapshotDetail
  }
})
export default class OneshotView extends Vue {
  private source: string = "";
  private target: TargetTypes = "body";
  private url: string = "";
  private snapshot: Snapshot | undefined = undefined;
  private scripts: Script[] = [];
  private matched: boolean | undefined = undefined;

  async scan() {
    const loadingComponent = this.$buefy.loading.open({
      container: this.$refs.element
    });

    try {
      const response = await axios.post<Oneshot>("/api/yara/oneshot", {
        source: this.source,
        url: this.url,
        target: this.target
      });

      const data = response.data;
      loadingComponent.close();

      this.snapshot = data.snapshot;
      this.scripts = data.scripts;
      this.matched = data.matched;

      this.$forceUpdate();
    } catch (error) {
      loadingComponent.close();

      const data = error.response.data as ErrorData;
      alert(data.detail);
    }
  }

  hasSnapshot(): boolean {
    return this.snapshot !== undefined;
  }

  message(): string {
    if (this.matched === undefined) {
      return "";
    } else if (this.matched) {
      return "Matched with YARA rule";
    } else {
      return "Not matched with YARA rule";
    }
  }

  messageType(): string {
    if (this.matched === undefined) {
      return "";
    } else if (this.matched) {
      return "is-warning";
    } else {
      return "is-success";
    }
  }
}
</script>
