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
                            query: { hostname: snapshot.hostname }
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
                            query: { ip_address: snapshot.ip_address }
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
                            query: { asn: snapshot.asn }
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
                            query: { server: snapshot.server }
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
                            query: { content_type: snapshot.content_type }
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
        <Scripts v-bind:scripts="scripts" />
      </b-tab-item>

      <b-tab-item label="DNS records">
        <DnsRecords v-bind:dnsRecords="dnsRecords" />
      </b-tab-item>
    </b-tabs>
  </div>
</template>

<script lang="ts">
import { Component, Prop, Vue } from "vue-property-decorator";
import axios, { AxiosError } from "axios";

import { Snapshot, Script, ErrorData, DnsRecord } from "@/types";
import Links from "@/components/links/Links.vue";
import Scripts from "@/components/scripts/Scripts.vue";
import DnsRecords from "@/components/dns_records/DnsRecords.vue";

// Google code prettifier
declare const PR: any;

@Component({
  components: {
    Links,
    Scripts,
    DnsRecords
  }
})
export default class SnapshotComponent extends Vue {
  @Prop() private snapshot!: Snapshot;
  @Prop() private propScripts!: Script[];
  @Prop() private propDnsRecords!: DnsRecord[];

  private scripts: Script[] = [];
  private dnsRecords: DnsRecord[] = [];

  public imageData(): string {
    return `data:Image/png;base64,${this.snapshot.screenshot}`;
  }

  async loadScripts() {
    try {
      const response = await axios.get<Script[]>("/api/scripts/search", {
        params: { snapshot_id: this.snapshot.id }
      });

      this.scripts = response.data;

      this.$forceUpdate();
    } catch (error) {
      const data = error.response.data as ErrorData;
      alert(data.detail);
    }
  }

  async loadDnsRecords() {
    try {
      const response = await axios.get<DnsRecord[]>("/api/dns_records/search", {
        params: { snapshot_id: this.snapshot.id }
      });

      this.dnsRecords = response.data;

      this.$forceUpdate();
    } catch (error) {
      const data = error.response.data as ErrorData;
      alert(data.detail);
    }
  }

  created() {
    if (this.propScripts !== undefined) {
      // oneshot scan returns a snapshot with scripts (as propScripts)
      this.scripts = this.propScripts;
      this.dnsRecords = this.propDnsRecords;
    } else if (this.snapshot.id !== undefined) {
      // load scripts if a snapshot has the ID
      this.loadScripts();
      this.loadDnsRecords();
    }
  }

  mounted() {
    PR.prettyPrint();
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
