<template>
  <div>
    <Loading v-if="getSnapshotTask.isRunning"></Loading>
    <Error
      :error="getSnapshotTask.last.error.response.data"
      v-else-if="getSnapshotTask.isError && getSnapshotTask.last !== undefined"
    ></Error>

    <div
      v-if="
        getSnapshotTask.last &&
        getSnapshotTask.last.value &&
        !getSnapshotTask.isError
      "
    >
      <b-message v-if="getSnapshotTask.last.value.processing" type="is-warning">
        <p><strong>Background tasks in progress...</strong></p>
        <p>
          The information below may be incomplete. Please reload this page after
          a while.
        </p>
      </b-message>
      <div class="box">
        <nav class="navbar">
          <div class="navbar-brand">
            <H2>
              {{ getSnapshotTask.last.value.url }}
            </H2>
          </div>
          <div class="navbar-menu">
            <div class="navbar-end">
              <Links
                :hostname="getSnapshotTask.last.value.hostname"
                :ipAddress="getSnapshotTask.last.value.ipAddress"
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
                          <td>{{ getSnapshotTask.last.value.id || "N/A" }}</td>
                        </tr>
                        <tr>
                          <th>Submitted URL</th>
                          <td>{{ getSnapshotTask.last.value.submittedUrl }}</td>
                        </tr>
                        <tr>
                          <th>Hostname</th>
                          <td>
                            <router-link
                              :to="{
                                name: 'Domain',
                                params: {
                                  hostname: getSnapshotTask.last.value.hostname,
                                },
                              }"
                              >{{ getSnapshotTask.last.value.hostname }}
                            </router-link>
                          </td>
                        </tr>

                        <tr>
                          <th>IP address</th>
                          <td>
                            <router-link
                              :to="{
                                name: 'IP address',
                                params: {
                                  ipAddress:
                                    getSnapshotTask.last.value.ipAddress,
                                },
                              }"
                              >{{ getSnapshotTask.last.value.ipAddress }}
                            </router-link>
                          </td>
                        </tr>

                        <tr>
                          <th>ASN</th>
                          <td>
                            <router-link
                              :to="{
                                name: 'Snapshots',
                                query: { asn: getSnapshotTask.last.value.asn },
                              }"
                              >{{ getSnapshotTask.last.value.asn }}
                            </router-link>
                          </td>
                        </tr>

                        <tr>
                          <th>Server</th>
                          <td>
                            <router-link
                              :to="{
                                name: 'Snapshots',
                                query: {
                                  server: getSnapshotTask.last.value.server,
                                },
                              }"
                              >{{ getSnapshotTask.last.value.server }}
                            </router-link>
                          </td>
                        </tr>

                        <tr>
                          <th>Content-Type</th>
                          <td>
                            <router-link
                              :to="{
                                name: 'Snapshots',
                                query: {
                                  contentType:
                                    getSnapshotTask.last.value.contentType,
                                },
                              }"
                              >{{ getSnapshotTask.last.value.contentType }}
                            </router-link>
                          </td>
                        </tr>

                        <tr>
                          <th>Created at</th>
                          <td>
                            <DatetimeWithDiff
                              v-bind:datetime="
                                getSnapshotTask.last.value.createdAt
                              "
                            />
                          </td>
                        </tr>
                      </tbody>
                    </table>
                  </div>
                </div>
                <div class="column is-half">
                  <H3> Screenshot </H3>
                  <Screenshot :snapshotId="getSnapshotTask.last.value.id" />
                </div>
              </div>
              <div class="column">
                <H3>SHA256(HTML)</H3>
                <router-link
                  :to="{
                    name: 'Snapshots',
                    query: { sha256: getSnapshotTask.last.value.html.id },
                  }"
                  >{{ getSnapshotTask.last.value.html.id }}
                </router-link>
              </div>
              <div class="column">
                <H3> Matched rules </H3>
                <Rules :rules="getSnapshotTask.last.value.rules" />
              </div>
            </div>
          </b-tab-item>

          <b-tab-item label="HTML">
            <pre><code class="html">{{ getSnapshotTask.last.value.html.content }}</code></pre>
          </b-tab-item>

          <b-tab-item label="Whois">
            <Whois :whois="getWhois(getSnapshotTask.last.value)" />
          </b-tab-item>

          <b-tab-item label="Certificate">
            <Certificate
              :certificate="getCertificate(getSnapshotTask.last.value)"
            />
          </b-tab-item>

          <b-tab-item label="Scripts">
            <Scripts :scripts="getSnapshotTask.last.value.scripts" />
          </b-tab-item>

          <b-tab-item label="DNS records">
            <DnsRecords :dnsRecords="getSnapshotTask.last.value.dnsRecords" />
          </b-tab-item>

          <b-tab-item label="Classifications">
            <Classifications
              :classifications="getSnapshotTask.last.value.classifications"
            />
          </b-tab-item>

          <b-tab-item v-if="yaraResult !== undefined" label="YARA matches">
            <YaraResultComponent :yaraResult="yaraResult" />
          </b-tab-item>
        </b-tabs>
      </div>
    </div>
  </div>
</template>

<script lang="ts">
import { defineComponent, onMounted, PropType } from "@vue/composition-api";
import { useAsyncTask } from "vue-concurrency";

import { API } from "@/api";
import Certificate from "@/components/certificate/Certificate.vue";
import Classifications from "@/components/classifications/Classifications.vue";
import DnsRecords from "@/components/dns_records/DnsRecords.vue";
import Links from "@/components/links/Links.vue";
import Rules from "@/components/rules/Buttons.vue";
import Screenshot from "@/components/screenshots/Screenshot.vue";
import Scripts from "@/components/scripts/Scripts.vue";
import DatetimeWithDiff from "@/components/ui/DatetimeWithDiff.vue";
import Error from "@/components/ui/Error.vue";
import H2 from "@/components/ui/H2.vue";
import H3 from "@/components/ui/H3.vue";
import Loading from "@/components/ui/Loading.vue";
import Whois from "@/components/whois/Whois.vue";
import YaraResultComponent from "@/components/yara/Result.vue";
import { Snapshot, YaraResult } from "@/types";
import { highlightCodeBlocks } from "@/utils/highlight";

export default defineComponent({
  name: "Snapshot",
  components: {
    Certificate,
    Classifications,
    DatetimeWithDiff,
    DnsRecords,
    Error,
    H2,
    H3,
    Links,
    Loading,
    Screenshot,
    Scripts,
    Whois,
    YaraResultComponent,
    Rules,
  },
  props: {
    snapshotId: {
      type: String,
      required: true,
    },
    yaraResult: {
      type: Object as PropType<YaraResult>,
      required: false,
    },
  },

  setup(props, context) {
    const getSnapshotTask = useAsyncTask<Snapshot, []>(async () => {
      return await API.getSnapshot(props.snapshotId);
    });

    const updateTitle = (url: string): void => {
      document.title = `${url} - Uzen`;
    };

    const getSnapshot = async () => {
      const snapshot = await getSnapshotTask.perform();
      updateTitle(snapshot.url);
    };

    const getWhois = (snapshot: Snapshot) => {
      return snapshot.whois?.content;
    };

    const getCertificate = (snapshot: Snapshot) => {
      return snapshot.certificate?.content;
    };

    onMounted(async () => {
      await getSnapshot();
      highlightCodeBlocks(context);
    });

    return { getSnapshotTask, getWhois, getCertificate };
  },
});
</script>
