<template>
  <div class="box">
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
                      <td>{{ snapshot.id || "N/A" }}</td>
                    </tr>
                    <tr>
                      <th>URL</th>
                      <td>{{ snapshot.url }}</td>
                    </tr>
                    <tr>
                      <th>Submitted URL</th>
                      <td>{{ snapshot.submitted_url }}</td>
                    </tr>
                    <tr>
                      <th>Hostname</th>
                      <td>
                        <router-link
                          :to="{
                            name: 'Snapshots',
                            query: { hostname: snapshot.hostname },
                          }"
                          >{{ snapshot.hostname }}
                        </router-link>
                      </td>
                    </tr>

                    <tr>
                      <th>IP address</th>
                      <td>
                        <router-link
                          :to="{
                            name: 'Snapshots',
                            query: { ip_address: snapshot.ip_address },
                          }"
                          >{{ snapshot.ip_address }}
                        </router-link>
                      </td>
                    </tr>

                    <tr>
                      <th>ASN</th>
                      <td>
                        <router-link
                          :to="{
                            name: 'Snapshots',
                            query: { asn: snapshot.asn },
                          }"
                          >{{ snapshot.asn }}
                        </router-link>
                      </td>
                    </tr>

                    <tr>
                      <th>Server</th>
                      <td>
                        <router-link
                          :to="{
                            name: 'Snapshots',
                            query: { server: snapshot.server },
                          }"
                          >{{ snapshot.server }}
                        </router-link>
                      </td>
                    </tr>

                    <tr>
                      <th>Content-Type</th>
                      <td>
                        <router-link
                          :to="{
                            name: 'Snapshots',
                            query: { content_type: snapshot.content_type },
                          }"
                          >{{ snapshot.content_type }}
                        </router-link>
                      </td>
                    </tr>

                    <tr>
                      <th>Created at</th>
                      <td>{{ snapshot.created_at || "N/A" }}</td>
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
            <h2 class="is-size-5 has-text-weight-bold middle">SHA256</h2>
            <router-link
              :to="{ name: 'Snapshots', query: { sha256: snapshot.sha256 } }"
              >{{ snapshot.sha256 }}
            </router-link>
          </div>
          <div class="column">
            <h2 class="is-size-5 has-text-weight-bold middle">Links</h2>
            <Links v-bind:snapshot="snapshot" />
          </div>
        </div>
      </b-tab-item>

      <b-tab-item label="Body">
        <pre class="prettyprint lang-html"> {{ snapshot.body }} </pre>
      </b-tab-item>

      <b-tab-item label="Whois">
        <pre>{{ snapshot.whois || "N/A" }}</pre>
      </b-tab-item>

      <b-tab-item label="Certificate">
        <pre>{{ snapshot.certificate || "N/A" }}</pre>
      </b-tab-item>

      <b-tab-item label="Scripts">
        <Scripts v-bind:scripts="snapshot.scripts" />
      </b-tab-item>

      <b-tab-item label="DNS records">
        <DnsRecords v-bind:dnsRecords="snapshot.dns_records" />
      </b-tab-item>

      <b-tab-item label="Classifications">
        <Classifications v-bind:classifications="snapshot.classifications" />
      </b-tab-item>

      <b-tab-item v-if="hasYaraResult()" label="YARA matches">
        <YaraResultComponent v-bind:yaraResult="yaraResult" />
      </b-tab-item>
    </b-tabs>
  </div>
</template>

<script lang="ts">
import { Component, Prop, Vue } from "vue-property-decorator";
import axios, { AxiosError } from "axios";

import {
  Snapshot,
  Script,
  ErrorData,
  DnsRecord,
  YaraResult,
  SnapshotWithYaraResult,
  Classification,
} from "@/types";
import Links from "@/components/links/Links.vue";
import Scripts from "@/components/scripts/Scripts.vue";
import DnsRecords from "@/components/dns_records/DnsRecords.vue";
import Classifications from "@/components/classifications/Classifications.vue";
import YaraResultComponent from "@/components/yara/Result.vue";

// Google code prettifier
declare const PR: any;

@Component({
  components: {
    Links,
    Scripts,
    DnsRecords,
    YaraResultComponent,
    Classifications,
  },
})
export default class SnapshotComponent extends Vue {
  @Prop() private snapshot!: Snapshot;
  @Prop() private yaraResult!: YaraResult;

  public imageData(): string {
    return `data:Image/png;base64,${this.snapshot.screenshot}`;
  }

  mounted() {
    PR.prettyPrint();
  }

  hasYaraResult(): boolean {
    return this.yaraResult !== undefined;
  }
}
</script>

<style scoped>
.header {
  margin-bottom: 10px;
}

.header h2 {
  color: #5892d0;
}

h2.middle {
  padding-bottom: 10px;
  margin-bottom: 10px;
  border-bottom: 2px solid lightgray;
}

pre {
  word-break: normal;
}
</style>
