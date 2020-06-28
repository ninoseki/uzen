<template>
  <div class="box" v-if="hasInformation()">
    <nav class="navbar">
      <div class="navbar-brand">
        <H2>Domain: {{ information.hostname }}</H2>
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
          <H3>
            DNS records
          </H3>
          <DnsRecords v-bind:dnsRecords="information.dnsRecords" />
        </div>
        <div class="column is-half">
          <H3>
            Live preview
          </H3>
          <Preview v-bind:hostname="information.hostname" />
        </div>
      </div>
    </div>

    <div class="column">
      <H3>
        Recent snapshots
        <Counter v-bind:hostname="information.hostname" />
      </H3>

      <Table v-if="hasSnapshots()" v-bind:snapshots="information.snapshots" />
      <p v-else>N/A</p>
    </div>

    <div class="column">
      <H3>
        Whois
      </H3>
      <pre>{{ information.whois || "N/A" }}</pre>
    </div>
  </div>
</template>

<script lang="ts">
import axios from "axios";
import { Component, Mixins } from "vue-mixin-decorator";

import DnsRecords from "@/components/dns_records/DnsRecords.vue";
import Links from "@/components/links/Links.vue";
import { ErrorDialogMixin } from "@/components/mixins";
import Preview from "@/components/screenshots/Preview.vue";
import Counter from "@/components/snapshots/Counter.vue";
import Table from "@/components/snapshots/TableWithScreenshot.vue";
import H2 from "@/components/ui/H2.vue";
import H3 from "@/components/ui/H3.vue";
import { DomainInformation, ErrorData } from "@/types";

@Component({
  components: {
    Counter,
    DnsRecords,
    H2,
    H3,
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
}
</script>
