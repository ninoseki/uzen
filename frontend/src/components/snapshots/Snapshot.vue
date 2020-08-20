<template>
  <div v-if="hasSnapshot()">
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
          <H2>
            {{ snapshot.url }}
          </H2>
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
                <H3>Info</H3>
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
                        <td>
                          <DatetimeWithDiff
                            v-bind:datetime="snapshot.createdAt"
                          />
                        </td>
                      </tr>
                    </tbody>
                  </table>
                </div>
              </div>
              <div class="column is-half">
                <H3>
                  Screenshot
                </H3>
                <Screenshot
                  v-bind:snapshot_id="snapshot.id"
                  v-bind:screenshot="snapshot.screenshot"
                />
              </div>
            </div>
            <div class="column">
              <H3>SHA256</H3>
              <router-link
                :to="{ name: 'Snapshots', query: { sha256: snapshot.sha256 } }"
                >{{ snapshot.sha256 }}
              </router-link>
            </div>
            <div class="column">
              <H3>
                Matched rules
              </H3>
              <Rules v-bind:rules="snapshot.rules" />
            </div>
          </div>
        </b-tab-item>

        <b-tab-item label="Body">
          <pre><code class="html">{{ snapshot.body }}</code></pre>
        </b-tab-item>

        <b-tab-item label="Whois">
          <Whois v-bind:whois="snapshot.whois" />
        </b-tab-item>

        <b-tab-item label="Certificate">
          <Certificate v-bind:certificate="snapshot.certificate" />
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
import axios from "axios";
import { Component, Mixins } from "vue-mixin-decorator";
import { Prop } from "vue-property-decorator";

import Certificate from "@/components/certificate/Certificate.vue";
import Classifications from "@/components/classifications/Classifications.vue";
import DnsRecords from "@/components/dns_records/DnsRecords.vue";
import Links from "@/components/links/Links.vue";
import {
  ErrorDialogMixin,
  HighlightComponentMixin,
  HighlightMixin,
} from "@/components/mixins";
import Rules from "@/components/rules/Buttons.vue";
import Screenshot from "@/components/screenshots/Screenshot.vue";
import Scripts from "@/components/scripts/Scripts.vue";
import DatetimeWithDiff from "@/components/ui/DatetimeWithDiff.vue";
import H2 from "@/components/ui/H2.vue";
import H3 from "@/components/ui/H3.vue";
import Whois from "@/components/whois/Whois.vue";
import YaraResultComponent from "@/components/yara/Result.vue";
import { ErrorData, Snapshot, YaraResult } from "@/types";

@Component({
  components: {
    Certificate,
    Classifications,
    DatetimeWithDiff,
    DnsRecords,
    H2,
    H3,
    Links,
    Rules,
    Screenshot,
    Scripts,
    Whois,
    YaraResultComponent,
  },
})
export default class SnapshotComponent extends Mixins<HighlightComponentMixin>(
  HighlightMixin,
  ErrorDialogMixin
) {
  @Prop() private id!: string;
  @Prop() private _snapshot!: Snapshot;
  @Prop() private yaraResult!: YaraResult;

  private snapshot: Snapshot | undefined = undefined;

  async load() {
    const loadingComponent = this.$buefy.loading.open({
      container: this.$el.firstElementChild,
    });

    try {
      const response = await axios.get<Snapshot>(`/api/snapshots/${this.id}`);
      this.snapshot = response.data;

      loadingComponent.close();
      this.$forceUpdate();
    } catch (error) {
      loadingComponent.close();

      const data = error.response.data as ErrorData;
      this.alertError(data);
    }
  }

  updateTitle(): void {
    const url = this.snapshot?.url || "undefined";
    document.title = `${url} - Uzen`;
  }

  async mounted() {
    this.snapshot = this._snapshot;
    this.$forceUpdate();

    if (this.snapshot === undefined) {
      await this.load();
    }
    this.updateTitle();
    this.highlightCodeBlocks();
  }

  hasYaraResult(): boolean {
    return this.yaraResult !== undefined;
  }

  hasSnapshot(): boolean {
    return this.snapshot !== undefined;
  }
}
</script>
