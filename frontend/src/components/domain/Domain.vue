<template>
  <div class="box" v-if="hasInformation()">
    <nav class="navbar">
      <div class="navbar-brand">
        <h2 class="is-size-4 has-text-weight-bold">
          Domain: {{ information.hostname }}
        </h2>
      </div>
      <div class="navbar-menu">
        <div class="navbar-end">
          <Links v-bind:hostname="information.hostname" type="domain" />
        </div>
      </div>
    </nav>

    <div class="column is-full">
      <div class="columns">
        <div class="column is-half">
          <h2 class="is-size-5 has-text-weight-bold middle">
            DNS records
          </h2>
          <DnsRecords v-bind:dnsRecords="information.dnsRecords" />
        </div>
        <div class="column is-half">
          <h2 class="is-size-5 has-text-weight-bold middle">
            Live preview
          </h2>
          <Preview v-bind:hostname="information.hostname" />
        </div>
      </div>
    </div>

    <div class="column">
      <h2 class="is-size-5 has-text-weight-bold middle">
        Recent snapshots
        <Counter v-bind:hostname="information.hostname" />
      </h2>

      <Table v-if="hasSnapshots()" v-bind:snapshots="information.snapshots" />
      <p v-else>N/A</p>
    </div>

    <div class="column">
      <h2 class="is-size-5 has-text-weight-bold middle">
        Whois
      </h2>
      <pre>{{ information.whois || "N/A" }}</pre>
    </div>
  </div>
</template>

<script lang="ts">
import { Component, Mixin, Mixins } from "vue-mixin-decorator";
import axios, { AxiosError } from "axios";
import moment from "moment/moment";

import { ErrorDialogMixin } from "@/components/mixins";

import Counter from "@/components/snapshots/Counter.vue";
import DnsRecords from "@/components/dns_records/DnsRecords.vue";
import Links from "@/components/links/Links.vue";
import Preview from "@/components/screenshots/Preview.vue";
import Screenshot from "@/components/screenshots/Screenshot.vue";
import Table from "@/components/snapshots/TableWithScreenshot.vue";

import {
  DomainInformation,
  Snapshot,
  SnapshotSearchResults,
  ErrorData,
} from "@/types";

@Component({
  components: {
    Counter,
    DnsRecords,
    Links,
    Preview,
    Table,
  },
})
export default class Domain extends Mixins<ErrorDialogMixin>(ErrorDialogMixin) {
  private information: DomainInformation | undefined = undefined;

  created() {
    this.load();
  }

  async load() {
    const loadingComponent = this.$buefy.loading.open({
      container: this.$el,
    });

    try {
      const hostname = this.$route.params.hostname;
      const res = await axios.get<DomainInformation>(`/api/domain/${hostname}`);
      this.information = res.data;

      loadingComponent.close();
      this.$forceUpdate();
    } catch (error) {
      loadingComponent.close();

      const data = error.response.data as ErrorData;
      this.alertError(data);
    }
  }

  hasInformation(): boolean {
    return this.information !== undefined;
  }

  hasSnapshots(): boolean {
    return (
      this.information !== undefined && this.information.snapshots.length > 0
    );
  }

  createdAtInLocalFormat(snapshot: Snapshot): string {
    if (snapshot.createdAt === undefined) {
      return "N/A";
    }
    return moment.parseZone(snapshot.createdAt).local().format();
  }
}
</script>
