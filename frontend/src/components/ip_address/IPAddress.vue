<template>
  <div class="box" v-if="hasInformation()">
    <nav class="navbar">
      <div class="navbar-brand">
        <h2 class="is-size-4 has-text-weight-bold">
          IP address: {{ information.ipAddress }}
        </h2>
      </div>
      <div class="navbar-menu">
        <div class="navbar-end">
          <Links v-bind:ipAddress="information.ipAddress" type="ip_address" />
        </div>
      </div>
    </nav>

    <div class="column is-full">
      <div class="columns">
        <div class="column is-half">
          <h2 class="is-size-5 has-text-weight-bold middle">
            Basic information
          </h2>
          <div class="table-container">
            <table class="table">
              <tbody>
                <tr>
                  <th>ASN</th>
                  <td>{{ information.asn }}</td>
                </tr>
                <tr>
                  <th>Description</th>
                  <td>{{ information.description }}</td>
                </tr>
                <tr>
                  <th>Country</th>
                  <td>{{ information.country }}</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
        <div class="column is-half">
          <h2 class="is-size-5 has-text-weight-bold middle">
            Live preview
          </h2>
          <Preview v-bind:hostname="information.ipAddress" />
        </div>
      </div>
    </div>

    <div class="column">
      <h2 class="is-size-5 has-text-weight-bold middle">
        Recent snapshots
        <Counter v-bind:ipAddress="information.ipAddress" />
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
import axios from "axios";
import { Component, Mixins } from "vue-mixin-decorator";

import Links from "@/components/links/Links.vue";
import { ErrorDialogMixin } from "@/components/mixins";
import Preview from "@/components/screenshots/Preview.vue";
import Counter from "@/components/snapshots/Counter.vue";
import Table from "@/components/snapshots/TableWithScreenshot.vue";
import { ErrorData, IPAddressInformation } from "@/types";

@Component({
  components: {
    Counter,
    Links,
    Preview,
    Table,
  },
})
export default class IPAddress extends Mixins<ErrorDialogMixin>(
  ErrorDialogMixin
) {
  private information: IPAddressInformation | undefined = undefined;

  created() {
    this.load();
  }

  async load() {
    const loadingComponent = this.$buefy.loading.open({
      container: this.$el,
    });

    try {
      const ipAddress = this.$route.params.ipAddress;
      const res = await axios.get<IPAddressInformation>(
        `/api/ip_address/${ipAddress}`
      );
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

<style scoped>
.table img {
  width: 180px;
}
</style>
