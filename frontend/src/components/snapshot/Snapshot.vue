<template>
  <div>
    <div class="column">
      <article class="message is-warning" v-if="snapshot.processing">
        <div class="message-body">
          <p><strong>Background tasks in progress...</strong></p>
          <p>
            The information below may be incomplete. Please reload this page
            after a while.
          </p>
        </div>
      </article>
    </div>
    <div class="columns">
      <aside class="column is-2 section">
        <p class="menu-label">Navigation</p>
        <ul class="menu-list">
          <li>
            <a
              @click="changeActiveState('summary')"
              :class="[activeState == 'summary' ? 'is-active' : '']"
            >
              Summary
            </a>
            <a
              @click="changeActiveState('html')"
              :class="[activeState == 'html' ? 'is-active' : '']"
            >
              HTML
            </a>
            <a
              @click="changeActiveState('text')"
              :class="[activeState == 'text' ? 'is-active' : '']"
            >
              Text
            </a>
            <a
              @click="changeActiveState('whois')"
              :class="[activeState == 'whois' ? 'is-active' : '']"
            >
              Whois
            </a>
            <a
              @click="changeActiveState('certificate')"
              :class="[activeState == 'certificate' ? 'is-active' : '']"
            >
              Certificate
            </a>
            <a
              @click="changeActiveState('scripts')"
              :class="[activeState == 'scripts' ? 'is-active' : '']"
            >
              Scripts
            </a>
            <a
              @click="changeActiveState('stylesheets')"
              :class="[activeState == 'stylesheets' ? 'is-active' : '']"
            >
              Stylesheets
            </a>
            <a
              @click="changeActiveState('indicators')"
              :class="[activeState == 'indicators' ? 'is-active' : '']"
            >
              Indicators
            </a>
            <a
              @click="changeActiveState('dnsRecords')"
              :class="[activeState == 'dnsRecords' ? 'is-active' : '']"
            >
              DNS records
            </a>
            <a
              @click="changeActiveState('har')"
              :class="[activeState == 'har' ? 'is-active' : '']"
            >
              HAR
            </a>
          </li>
        </ul>
      </aside>

      <div class="column">
        <div class="box">
          <Navbar :snapshot="snapshot"></Navbar>

          <div v-if="activeState === 'summary'">
            <Summary :snapshot="snapshot"></Summary>
          </div>
          <div v-else-if="activeState === 'html'">
            <HTML :sha256="snapshot.html.sha256"></HTML>
          </div>
          <div v-else-if="activeState === 'text'">
            <TextComponent :sha256="snapshot.html.sha256"></TextComponent>
          </div>
          <div v-else-if="activeState === 'whois'">
            <Whois :whoisId="snapshot.whois.id" v-if="snapshot.whois?.id" />
          </div>
          <div v-else-if="activeState === 'certificate'">
            <Certificate
              :id="snapshot.certificate.id"
              v-if="snapshot.certificate"
            />
            <NA v-else></NA>
          </div>
          <div v-else-if="activeState === 'scripts'">
            <Scripts :scripts="snapshot.scripts" />
          </div>
          <div v-else-if="activeState === 'stylesheets'">
            <Stylesheets :stylesheets="snapshot.stylesheets" />
          </div>
          <div v-else-if="activeState === 'indicators'">
            <Indicators :snapshotId="snapshot.id" />
          </div>
          <div v-else-if="activeState === 'dnsRecords'">
            <DnsRecords :dnsRecords="snapshot.dnsRecords" />
          </div>
          <div v-else-if="activeState === 'har'">
            <HAR :snapshotId="snapshot.id" />
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script lang="ts">
import { defineComponent, PropType, ref } from "vue";

import Certificate from "@/components/certificate/CertificateWrapper.vue";
import DnsRecords from "@/components/dns_record/DnsRecords.vue";
import HAR from "@/components/har/HARWrapper.vue";
import HTML from "@/components/html/HTMLWrapper.vue";
import Indicators from "@/components/indicator/IndicatorsWrapper.vue";
import Scripts from "@/components/script/Scripts.vue";
import Navbar from "@/components/snapshot/Navbar.vue";
import Summary from "@/components/snapshot/Summary.vue";
import Stylesheets from "@/components/stylesheet/Stylesheets.vue";
import TextComponent from "@/components/text/TextWrapper.vue";
import NA from "@/components/ui/NA.vue";
import Whois from "@/components/whois/WhoisWrapper.vue";
import { Snapshot } from "@/types";

type States =
  | "certificate"
  | "classifications"
  | "dnsRecords"
  | "har"
  | "html"
  | "indicators"
  | "scripts"
  | "stylesheets"
  | "summary"
  | "text"
  | "whois";

export default defineComponent({
  name: "SnapshotItem",
  components: {
    Certificate,
    DnsRecords,
    HAR,
    HTML,
    NA,
    Indicators,
    Navbar,
    Scripts,
    Summary,
    Stylesheets,
    TextComponent,
    Whois,
  },
  props: {
    snapshot: {
      type: Object as PropType<Snapshot>,
      required: true,
    },
  },

  setup() {
    // set active tab
    const activeState = ref<States>("summary");

    const changeActiveState = (newState: States) => {
      activeState.value = newState;
    };

    return {
      activeState,
      changeActiveState,
    };
  },
});
</script>

<style scoped>
a.is-active {
  background-color: transparent;
  color: #4a4a4a;
  font-weight: bold;
}
</style>
