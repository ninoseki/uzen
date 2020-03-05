<template>
  <div class="listItem">
    <b-tabs type="is-boxed">
      <b-tab-item label="Summary">
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
                  </tbody>
                </table>
              </div>
            </div>
            <div class="column is-half">
              <h2 class="is-size-5 has-text-weight-bold middle">Screenshot</h2>
              <img :src="this.imageData()" alt="screenshot" />
            </div>
          </div>
          <div class="column">
            <h2 class="is-size-5 has-text-weight-bold middle">Links</h2>
            <Links v-bind:snapshot="data" />
          </div>
        </div>
      </b-tab-item>

      <b-tab-item label="Body">
        <pre class="prettyprint lang-html"> {{ data.body }} </pre>
      </b-tab-item>

      <b-tab-item label="Whois">
        <pre>{{ data.whois || "N/A" }}</pre>
      </b-tab-item>

      <b-tab-item label="Certificate">
        <pre>{{ data.certificate || "N/A" }}</pre>
      </b-tab-item>
    </b-tabs>
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

.listItem h2.middle {
  padding-bottom: 10px;
  margin-bottom: 10px;
  border-bottom: 2px solid lightgray;
}

.listItem pre {
  max-height: 500px;
  overflow: auto;
  word-break: normal;
}
</style>
