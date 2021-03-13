<template>
  <div>
    <b-message v-if="snapshot.processing" type="is-warning" has-icon>
      <p><strong>Background tasks in progress...</strong></p>
      <p>
        The information below may be incomplete. Please reload this page after a
        while.
      </p>
    </b-message>
    <div class="box">
      <Navbar :snapshot="snapshot"></Navbar>

      <b-tabs type="is-boxed" v-model="activeTab">
        <b-tab-item label="Summary" :value="'summary'">
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
                        <td>
                          {{ truncate(snapshot.submittedUrl, 48) }}
                        </td>
                      </tr>
                      <tr>
                        <th>Hostname</th>
                        <td>
                          <router-link
                            :to="{
                              name: 'Domain',
                              params: {
                                hostname: snapshot.hostname,
                              },
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
                              params: {
                                ipAddress: snapshot.ipAddress,
                              },
                            }"
                            >{{ snapshot.ipAddress }}
                            {{ countryCodeToEmoji(snapshot.countryCode) }}
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
                <Request :requestHeaders="snapshot.requestHeaders"></Request>
              </div>
              <div class="column is-half">
                <H3> Screenshot </H3>
                <Screenshot :snapshotId="snapshot.id" />
              </div>
            </div>
            <div class="column">
              <H3>SHA256 hash (HTML)</H3>
              <router-link
                :to="{
                  name: 'Snapshots',
                  query: { htmlHash: snapshot.html.sha256 },
                }"
                >{{ snapshot.html.sha256 }}
              </router-link>
            </div>
            <div class="column">
              <H3> Classifications </H3>
              <ClassificationTags :classifications="snapshot.classifications" />
            </div>
            <div class="column">
              <H3> Matched rules </H3>
              <Rules :rules="snapshot.rules" />
            </div>
          </div>
        </b-tab-item>

        <b-tab-item label="HTML" :value="'html'">
          <div v-if="isHTMLActivated">
            <HTML :sha256="snapshot.html.sha256"></HTML>
          </div>
        </b-tab-item>

        <b-tab-item label="Whois" :value="'whois'">
          <div v-if="isWhoisActivated">
            <Whois
              :whoisId="snapshot.whois.id"
              v-if="snapshot.whois && snapshot.whois.id"
            />
          </div>
        </b-tab-item>

        <b-tab-item label="Certificate" :value="'certificate'">
          <div v-if="isCertificateActivated">
            <Certificate
              :sha256="snapshot.certificate.sha256"
              v-if="snapshot.certificate"
            />
            <NA v-else></NA>
          </div>
        </b-tab-item>

        <b-tab-item label="Scripts">
          <Scripts :scripts="snapshot.scripts" />
        </b-tab-item>

        <b-tab-item label="Stylehseets">
          <Stylesheets :stylesheets="snapshot.stylesheets" />
        </b-tab-item>

        <b-tab-item label="DNS records">
          <DnsRecords :dnsRecords="snapshot.dnsRecords" />
        </b-tab-item>

        <b-tab-item label="HAR" :value="'har'">
          <div v-if="isHARActivated">
            <HAR :snapshotId="snapshot.id" />
          </div>
        </b-tab-item>

        <b-tab-item v-if="yaraResult !== undefined" label="YARA matches">
          <YaraResultComponent :yaraResult="yaraResult" />
        </b-tab-item>
      </b-tabs>
    </div>
  </div>
</template>

<script lang="ts">
import { defineComponent, PropType, ref, watch } from "@vue/composition-api";

import Certificate from "@/components/certificate/CertificateWrapper.vue";
import ClassificationTags from "@/components/classification/Tags.vue";
import DnsRecords from "@/components/dns_record/DnsRecords.vue";
import HAR from "@/components/har/HARWrapper.vue";
import HTML from "@/components/html/HTMLWrapper.vue";
import Rules from "@/components/rule/Buttons.vue";
import Screenshot from "@/components/screenshot/Screenshot.vue";
import Scripts from "@/components/script/Scripts.vue";
import Navbar from "@/components/snapshot/Navbar.vue";
import Request from "@/components/snapshot/Request.vue";
import Stylesheets from "@/components/stylesheet/Stylesheets.vue";
import DatetimeWithDiff from "@/components/ui/DatetimeWithDiff.vue";
import H3 from "@/components/ui/H3.vue";
import NA from "@/components/ui/NA.vue";
import Whois from "@/components/whois/WhoisWrapper.vue";
import YaraResultComponent from "@/components/yara/Result.vue";
import { Snapshot, YaraResult } from "@/types";
import { countryCodeToEmoji } from "@/utils/country";
import { truncate } from "@/utils/truncate";

export default defineComponent({
  name: "Snapshot",
  components: {
    Certificate,
    ClassificationTags,
    DatetimeWithDiff,
    DnsRecords,
    H3,
    HAR,
    HTML,
    NA,
    Navbar,
    Request,
    Rules,
    Screenshot,
    Scripts,
    Stylesheets,
    Whois,
    YaraResultComponent,
  },
  props: {
    snapshot: {
      type: Object as PropType<Snapshot>,
      required: true,
    },
    yaraResult: {
      type: Object as PropType<YaraResult>,
      required: false,
    },
  },

  setup() {
    // set active tab
    const activeTab = ref("summary");
    const isHTMLActivated = ref(false);
    const isWhoisActivated = ref(false);
    const isHARActivated = ref(false);
    const isCertificateActivated = ref(false);

    watch(
      activeTab,
      // eslint-disable-next-line no-unused-vars
      (active, _last) => {
        if (active === "certificate") {
          isCertificateActivated.value = true;
        }

        if (active === "html") {
          isHTMLActivated.value = true;
        }

        if (active === "whois") {
          isWhoisActivated.value = true;
        }

        if (active === "har") {
          isHARActivated.value = true;
        }
      }
    );

    return {
      activeTab,
      countryCodeToEmoji,
      isCertificateActivated,
      isHARActivated,
      isHTMLActivated,
      isWhoisActivated,
      truncate,
    };
  },
});
</script>
