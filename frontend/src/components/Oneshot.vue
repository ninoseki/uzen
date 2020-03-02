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
      <b-field label="YARA rule">
        <b-input
          class="is-expanded"
          type="textarea"
          placeholder="rule foo: bar {strings: $a = 'lmn' condition: $a}"
          v-model="source"
        ></b-input>
      </b-field>
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
      <SnapshotDetail v-if="hasSnapshot()" v-bind:data="snapshot" />
    </div>
  </div>
</template>

<script lang="ts">
import { Component, Prop, Vue } from "vue-property-decorator";
import axios, { AxiosError } from "axios";

import { ErrorData, Snapshot, Oneshot } from "@/types";

import SnapshotDetail from "@/components/SnapshotDetail.vue";

@Component({
  components: {
    SnapshotDetail
  }
})
export default class OneshotView extends Vue {
  private source: string = "";
  private url: string = "";
  private snapshot: Snapshot | undefined = undefined;
  private matched: boolean | undefined = undefined;

  async scan() {
    const loadingComponent = this.$buefy.loading.open({
      container: this.$refs.element
    });

    try {
      const response = await axios.post<Oneshot>("/api/yara/oneshot", {
        source: this.source,
        url: this.url
      });

      const data = response.data;
      loadingComponent.close();

      this.snapshot = data.snapshot;
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
