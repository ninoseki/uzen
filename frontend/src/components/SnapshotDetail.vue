<template>
  <div class="listItem">
    <div class="listItem header">
      <h2 class="is-size-5">{{ data.url }} ({{ data.created_at }})</h2>
    </div>

    <div class="dFlex flexAlignCenter flexJustSpace">
      <div class="dFlex flexAlignCenter flexJustSpace">
        <span>
          <strong>Hostname:</strong>
          {{ data.hostname }}
        </span>
      </div>
      <div class="dFlex flexAlignCenter flexJustSpace">
        <span>
          <strong>IP address:</strong>
          {{ data.ip_address }}
        </span>
      </div>
      <div class="dFlex flexAlignCenter flexJustSpace">
        <span>
          <strong>Server:</strong>
          {{ data.server }}
        </span>
      </div>
      <div class="dFlex flexAlignCenter flexJustSpace">
        <span>
          <strong>Content type:</strong>
          {{ data.content_type }}
        </span>
      </div>
      <div class="dFlex flexAlignCenter flexJustSpace">
        <span>
          <strong>Content length:</strong>
          {{ data.content_length }}
        </span>
      </div>
    </div>

    <div class="column is-full details">
      <div class="columns">
        <div class="column is-half screenshot">
          <img :src="this.imageData()" alt="screenshot" />
        </div>
        <div class="column is-half body">
          <pre class="prettyprint lang-html">
            {{ data.body }}
          </pre>
        </div>
      </div>
    </div>
  </div>
</template>

<script lang="ts">
import { Component, Prop, Vue } from "vue-property-decorator";

import { Snapshot } from "@/types";

@Component
export default class SnapshotDetail extends Vue {
  @Prop() private data!: Snapshot;

  public imageData(): string {
    return `data:Image/png;base64,${this.data.screenshot}`;
  }
}
</script>

<style scoped>
.fade-enter-active,
.fade-leave-active {
  transition: opacity 0.5s;
}
.fade-enter, .fade-leave-to /* .fade-leave-active below version 2.1.8 */ {
  opacity: 0;
}
.listItem {
  display: block;
  padding: 32px;
  background-color: #fff;
  -webkit-transform: scale(1);
  transform: scale(1);
  -webkit-transition: all 0.15s ease;
  transition: all 0.2s ease;
  z-index: 1;
  position: relative;
  cursor: pointer;
  overflow: hidden;
}

.listItem:not(:first-child) {
  border-top: 3px solid #eee;
}

.listItem:first-child {
  border-top-left-radius: 6px;
  border-top-right-radius: 6px;
}

.listItem:last-child {
  border-bottom-left-radius: 6px;
  border-bottom-right-radius: 6px;
}

.list {
  box-shadow: 0 10px 30px 0 rgba(0, 0, 0, 0.1);
}
.listItem .header {
  margin-bottom: 10px;
}

.listItem .header h2 {
  color: #5892d0;
}

.dFlex {
  display: flex;
}
.flexAlignCenter {
  align-items: center;
}
.flexJustSpace {
  justify-content: space-between;
}

.prettyprint {
  background-color: #f6f8fa;
  border-radius: 3px;
  max-height: 500px;
  overflow: auto;
  word-break: normal;
}
</style>
