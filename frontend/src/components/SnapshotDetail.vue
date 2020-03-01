<template>
  <div class="listItem">
    <div class="listItem header">
      <h2 class="is-size-5">{{ data.id }}: {{ data.url }}</h2>
    </div>

    <b-table :data="rows" :columns="columns"></b-table>

    <div class="column is-full details">
      <div class="columns">
        <div class="column is-half screenshot">
          <h2 class="is-size-6 has-text-weight-bold middle">Screenshot</h2>
          <img :src="this.imageData()" alt="screenshot" />
        </div>
        <div class="column is-half body">
          <h2 class="is-size-6 has-text-weight-bold middle">Body</h2>
          <pre class="prettyprint lang-html">
            {{ data.body }}
          </pre>
        </div>
      </div>
    </div>

    <div>
      <h2 class="is-size-6 has-text-weight-bold middle">Links</h2>
      <Links v-bind:snapshot="data" />
    </div>
  </div>
</template>

<script lang="ts">
import { Component, Prop, Vue } from "vue-property-decorator";

import { Snapshot } from "@/types";
import Links from "@/components/Links.vue";

// Google code prettifier
declare const PR: any;

@Component({
  components: {
    Links
  }
})
export default class SnapshotDetail extends Vue {
  @Prop() private data!: Snapshot;

  private rows = [this.data];

  private columns = [
    {
      field: "id",
      label: "ID"
    },
    {
      field: "hostname",
      label: "Hostname"
    },
    {
      field: "ip_address",
      label: "IP address"
    },
    {
      field: "server",
      label: "Server"
    },
    {
      field: "content_type",
      label: "Content-Type"
    },
    {
      field: "content_length",
      label: "Content-Length"
    },
    {
      field: "created_at",
      label: "Created at"
    }
  ];

  public imageData(): string {
    return `data:Image/png;base64,${this.data.screenshot}`;
  }

  mounted() {
    PR.prettyPrint();
  }
}
</script>

<style scoped>
.listItem {
  display: block;
  padding: 10px;
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

.listItem .header {
  margin-bottom: 10px;
}

.listItem .header h2 {
  color: #5892d0;
}

h2.middle {
  padding-bottom: 10px;
  margin-bottom: 10px;
  border-bottom: 2px solid lightgray;
}

.prettyprint {
  max-height: 500px;
  overflow: auto;
  word-break: normal;
}
</style>
