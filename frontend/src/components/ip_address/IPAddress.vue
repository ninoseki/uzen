<template>
  <div>
    <Loading v-if="getIPAddressTask.isRunning"></Loading>
    <Error
      :error="getIPAddressTask.last.error.response.data"
      v-else-if="
        getIPAddressTask.isError && getIPAddressTask.last !== undefined
      "
    ></Error>

    <div
      class="box"
      v-else-if="
        getIPAddressTask.last &&
        getIPAddressTask.last.value &&
        !getIPAddressTask.isError
      "
    >
      <nav class="navbar">
        <div class="navbar-brand">
          <H2
            >IP address: {{ getIPAddressTask.last.value.ipAddress }}
            {{
              countryCodeToEmoji(getIPAddressTask.last.value.countryCode)
            }}</H2
          >
        </div>
        <div class="navbar-menu">
          <div class="navbar-end">
            <Links
              v-bind:ipAddress="getIPAddressTask.last.value.ipAddress"
              type="ip_address"
            />
          </div>
        </div>
      </nav>

      <div class="column is-full">
        <div class="columns">
          <div class="column is-half">
            <H3>Basic information</H3>
            <div class="table-container">
              <table class="table">
                <tbody>
                  <tr>
                    <th>ASN</th>
                    <td>{{ getIPAddressTask.last.value.asn }}</td>
                  </tr>
                  <tr>
                    <th>Description</th>
                    <td>{{ getIPAddressTask.last.value.description }}</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>
          <div class="column is-half">
            <H3>Live preview</H3>
            <Preview v-bind:hostname="getIPAddressTask.last.value.ipAddress" />
          </div>
        </div>
      </div>

      <div class="column">
        <H3>
          Recent snapshots
          <Counter v-bind:ipAddress="getIPAddressTask.last.value.ipAddress" />
        </H3>
        <ScreenshotTable
          v-if="hasSnapshots()"
          v-bind:snapshots="getIPAddressTask.last.value.snapshots"
        />
        <p v-else>N/A</p>
      </div>

      <div class="column">
        <H3> Whois </H3>
        <pre>{{ getIPAddressTask.last.value.whois || "N/A" }}</pre>
      </div>
    </div>
  </div>
</template>

<script lang="ts">
import { defineComponent } from "@vue/composition-api";
import { useAsyncTask } from "vue-concurrency";

import { API } from "@/api";
import Links from "@/components/link/Links.vue";
import Preview from "@/components/screenshot/Preview.vue";
import Counter from "@/components/snapshot/Counter.vue";
import ScreenshotTable from "@/components/snapshot/TableWithScreenshot.vue";
import Error from "@/components/ui/Error.vue";
import H2 from "@/components/ui/H2.vue";
import H3 from "@/components/ui/H3.vue";
import Loading from "@/components/ui/Loading.vue";
import { IPAddressInformation } from "@/types";
import { countryCodeToEmoji } from "@/utils/country";

export default defineComponent({
  name: "Domain",
  components: {
    Counter,
    Error,
    H2,
    H3,
    Links,
    Loading,
    Preview,
    ScreenshotTable,
  },
  setup(_, context) {
    const hostname = context.root.$route.params.ipAddress;

    const getIPAddressTask = useAsyncTask<IPAddressInformation, []>(
      async () => {
        return API.getIPAddressInformation(hostname);
      }
    );

    getIPAddressTask.perform();

    const hasSnapshots = () => {
      return (getIPAddressTask.last?.value?.snapshots.length || 0) > 0;
    };

    return { getIPAddressTask, hasSnapshots, countryCodeToEmoji };
  },
});
</script>

<style scoped>
.table img {
  width: 180px;
}
</style>
