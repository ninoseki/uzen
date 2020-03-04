<template>
  <div class="listItem">
    <div class="column is-full">
      <div class="columns">
        <div class="column is-half">
          <h2 class="is-size-5 has-text-weight-bold middle">Info</h2>
          <div class="table-container">
            <table class="table">
              <tbody>
                <tr>
                  <th>ID</th>
                  <td>{{ data.id }}</td>
                </tr>
                <tr>
                  <th>URL</th>
                  <td>{{ data.url }}</td>
                </tr>
                <tr>
                  <th>Hostname</th>
                  <td>{{ data.hostname }}</td>
                </tr>

                <tr>
                  <th>IP address</th>
                  <td>{{ data.ip_address }}</td>
                </tr>

                <tr>
                  <th>ASN</th>
                  <td>{{ data.asn }}</td>
                </tr>

                <tr>
                  <th>Server</th>
                  <td>{{ data.server }}</td>
                </tr>

                <tr>
                  <th>Content-Type</th>
                  <td>{{ data.content_type }}</td>
                </tr>

                <tr>
                  <th>SHA256</th>
                  <td>{{ data.sha256 }}</td>
                </tr>

                <tr>
                  <th>Created at</th>
                  <td>{{ data.created_at }}</td>
                </tr>

                <tr>
                  <th>Links</th>
                  <td>
                    <Links v-bind:snapshot="data" />
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
        <div class="column is-half">
          <h2 class="is-size-5 has-text-weight-bold middle">Screenshot</h2>
          <img :src="this.imageData()" alt="screenshot" />
        </div>
      </div>
    </div>

    <div class="column">
      <h2 class="is-size-5 has-text-weight-bold middle" @click="showBody = !showBody">
        Body
        <b-icon :icon="showBody ? 'menu-down' : 'menu-up'"></b-icon>
      </h2>
      <pre v-show="showBody" class="prettyprint lang-html"> {{ data.body }} </pre>
    </div>

    <div class="column">
      <h2 class="is-size-5 has-text-weight-bold middle" @click="showWhois = !showWhois">
        Whois
        <b-icon :icon="showWhois ? 'menu-down' : 'menu-up'"></b-icon>
      </h2>
      <pre v-if="showWhois" class="prettyprint">{{ data.whois }}</pre>
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

  private showBody = false;
  private showWhois = false;

  public imageData(): string {
    return `data:Image/png;base64,${this.data.screenshot}`;
  }

  public normalizedASN(): string {
    return this.data.asn.split(" ")[0];
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
  margin-top: 20px;
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
