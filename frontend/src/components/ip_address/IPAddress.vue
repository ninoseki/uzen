<template>
  <div class="box" v-if="hasInformation()">
    <h2 class="is-size-4 has-text-weight-bold middle">
      IP address: {{ information.ipAddress }}
    </h2>

    <div class="column is-full">
      <div class="columns">
        <div class="column is-half">
          <h2 class="is-size-5 has-text-weight-bold middle">
            Live preview
          </h2>
          <Preview v-bind:hostname="information.ipAddress" />
        </div>
        <div class="column is-half">
          <h2 class="is-size-5 has-text-weight-bold middle">
            Basic information
          </h2>
          <div class="table-container">
            <table class="table">
              <tbody>
                <tr>
                  <th>Country</th>
                  <td>{{ information.country }}</td>
                </tr>
                <tr>
                  <th>Organization</th>
                  <td>{{ information.org }}</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>

    <div class="column">
      <h2 class="is-size-5 has-text-weight-bold middle">
        Recent snapshots
      </h2>
      <b-table v-if="hasSnapshots()" :data="information.snapshots">
        <template slot-scope="props">
          <b-table-column field="url" label="URL">
            <router-link
              :to="{
                name: 'Snapshot',
                params: { id: props.row.id },
              }"
            >
              {{ props.row.url }}
            </router-link>
          </b-table-column>

          <b-table-column field="status" label="Status">
            {{ props.row.status }}
          </b-table-column>

          <b-table-column field="contentType" label="Content Type">
            {{ props.row.contentType }}
          </b-table-column>

          <b-table-column field="contentLength" label="Content length">
            {{ props.row.contentLength }}
          </b-table-column>

          <b-table-column field="createdAt" label="Created at">
            {{ createdAtInLocalFormat(props.row) }}
          </b-table-column>

          <b-table-column field="screenshot" label="Screenshot">
            <Screenshot v-bind:snapshot_id="props.row.id" />
          </b-table-column>
        </template>
      </b-table>
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
import Preview from "@/components/screenshots/Preview.vue";
import Screenshot from "@/components/screenshots/Screenshot.vue";

import { IPAddressInformation, Snapshot, ErrorData } from "@/types";

@Component({
  components: {
    Preview,
    Screenshot,
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

  createdAtInLocalFormat(snapshot: Snapshot): string {
    if (snapshot.createdAt === undefined) {
      return "N/A";
    }
    return moment.parseZone(snapshot.createdAt).local().format();
  }
}
</script>

<style scoped>
.table img {
  width: 180px;
}
</style>
