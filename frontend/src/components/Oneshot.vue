<template>
  <div>
    <div class="box">
      <b-field label="URL">
        <b-input
          class="control is-expanded"
          placeholder="http://example.com"
          type="url"
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
      <SnapshotComponent
        v-if="hasSnapshot()"
        v-bind:snapshot="oneshot.snapshot"
        v-bind:yaraResult="yaraResult()"
        v-bind:propScripts="oneshot.scripts"
        v-bind:propDnsRecords="oneshot.dnsRecords"
      />
    </div>
  </div>
</template>

<script lang="ts">
import { Component, Prop, Vue } from "vue-property-decorator";
import axios, { AxiosError } from "axios";

import {
  ErrorData,
  Snapshot,
  Oneshot,
  TargetTypes,
  Script,
  DnsRecord,
  YaraResult
} from "@/types";

import SnapshotComponent from "@/components/snapshots/Snapshot.vue";
import BasicYaraForm from "@/components/yara/BasicForm.vue";

@Component({
  components: {
    BasicYaraForm,
    SnapshotComponent
  }
})
export default class OneshotView extends Vue {
  private source: string = "";
  private target: TargetTypes = "body";
  private url: string = "";
  private oneshot: Oneshot | undefined = undefined;

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

      this.oneshot = response.data;
      loadingComponent.close();

      this.$forceUpdate();
    } catch (error) {
      loadingComponent.close();

      const data = error.response.data as ErrorData;
      alert(data.detail);
    }
  }

  hasSnapshot(): boolean {
    return this.oneshot?.snapshot !== undefined;
  }

  matched(): boolean {
    if (this.oneshot?.matched === undefined) {
      return false;
    }
    return this.oneshot.matched;
  }

  message(): string {
    if (this.matched()) {
      return "Matched with YARA rule";
    }
    return "Not matched with YARA rule";
  }

  messageType(): string {
    if (this.matched()) {
      return "is-warning";
    }
    return "is-success";
  }

  yaraResult(): YaraResult | undefined {
    if (this.oneshot?.matches !== undefined) {
      const result: YaraResult = {
        snapshot_id: -1,
        script_id: undefined,
        target: this.target,
        matches: this.oneshot.matches
      };
      return result;
    }
    return undefined;
  }
}
</script>
