<template>
  <div>
    <b-message v-if="snapshot.processing" type="is-warning">
      <p><strong>Background tasks in progress...</strong></p>
      <p>
        The information below may be incomplete. Please reload this page after a
        while.
      </p>
    </b-message>
    <div class="box">
      <nav class="navbar">
        <div class="navbar-brand">
          <h2 class="is-size-4 has-text-weight-bold">
            {{ snapshot.url }}
          </h2>
        </div>
        <div class="navbar-menu">
          <div class="navbar-end">
            <Links
              v-bind:hostname="snapshot.hostname"
              v-bind:ipAddress="snapshot.ipAddress"
            />
          </div>
        </div>
      </nav>
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
                        <th>Submitted URL</th>
                        <td>{{ snapshot.submittedUrl }}</td>
                      </tr>
                      <tr>
                        <th>Hostname</th>
                        <td>
                          <router-link
                            :to="{
                              name: 'Domain',
                              params: { hostname: snapshot.hostname },
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
                              name: 'IP address',
                              params: { ipAddress: snapshot.ipAddress },
                            }"
                            >{{ snapshot.ipAddress }}
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
                              query: { contentType: snapshot.contentType },
                            }"
                            >{{ snapshot.contentType }}
                          </router-link>
                        </td>
                      </tr>

                      <tr>
                        <th>Created at</th>
                        <td>{{ createdAtInLocalFormat() }}</td>
                      </tr>
                    </tbody>
                  </table>
                </div>
              </div>
              <div class="column is-half">
                <h2 class="is-size-5 has-text-weight-bold middle">
                  Screenshot
                </h2>
                <Screenshot
                  v-bind:snapshot_id="snapshot.id"
                  v-bind:screenshot="snapshot.screenshot"
                />
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
              <h2 class="is-size-5 has-text-weight-bold middle">
                Matched rules
              </h2>
              <Rules v-bind:rules="snapshot.rules" />
            </div>
          </div>
        </b-tab-item>

        <b-tab-item label="Body">
          <pre><code class="html">{{ snapshot.body }}</code></pre>
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
          <DnsRecords v-bind:dnsRecords="snapshot.dnsRecords" />
        </b-tab-item>

        <b-tab-item label="Classifications">
          <Classifications v-bind:classifications="snapshot.classifications" />
        </b-tab-item>

        <b-tab-item v-if="hasYaraResult()" label="YARA matches">
          <YaraResultComponent v-bind:yaraResult="yaraResult" />
        </b-tab-item>
      </b-tabs>
    </div>
  </div>
</template>

<script lang="ts">
import { Component, Mixin, Mixins } from "vue-mixin-decorator";
import { Prop } from "vue-property-decorator";
import moment from "moment/moment";

import {
  Snapshot,
  Script,
  ErrorData,
  DnsRecord,
  YaraResult,
  SnapshotWithYaraResult,
  Classification,
} from "@/types";

import Classifications from "@/components/classifications/Classifications.vue";
import DnsRecords from "@/components/dns_records/DnsRecords.vue";
import Links from "@/components/links/Links.vue";
import Rules from "@/components/rules/Buttons.vue";
import Screenshot from "@/components/screenshots/Screenshot.vue";
import Scripts from "@/components/scripts/Scripts.vue";
import YaraResultComponent from "@/components/yara/Result.vue";

import { HighlightMixin } from "@/components/mixins";

@Component({
  components: {
    Classifications,
    DnsRecords,
    Links,
    Rules,
    Screenshot,
    Scripts,
    YaraResultComponent,
  },
})
export default class SnapshotComponent extends Mixins<HighlightMixin>(
  HighlightMixin
) {
  @Prop() private snapshot!: Snapshot;
  @Prop() private yaraResult!: YaraResult;

  mounted() {
    this.highlightCodeBlocks();
  }

  hasYaraResult(): boolean {
    return this.yaraResult !== undefined;
  }

  createdAtInLocalFormat(): string {
    if (this.snapshot.createdAt === undefined) {
      return "N/A";
    }
    return moment.parseZone(this.snapshot.createdAt).local().format();
  }
}
</script>
