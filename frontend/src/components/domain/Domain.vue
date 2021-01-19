<template>
  <div>
    <Loading v-if="getDomainTask.isRunning"></Loading>
    <Error
      :error="getDomainTask.last.error.response.data"
      v-else-if="getDomainTask.isError && getDomainTask.last !== undefined"
    ></Error>

    <div
      class="box"
      v-else-if="
        getDomainTask.last && getDomainTask.last.value && !getDomainTask.isError
      "
    >
      <nav class="navbar">
        <div class="navbar-brand">
          <H2>Domain: {{ getDomainTask.last.value.hostname }}</H2>
        </div>
        <div class="navbar-menu">
          <div class="navbar-end">
            <Links
              :hostname="getDomainTask.last.value.hostname"
              type="domain"
            />
          </div>
        </div>
      </nav>

      <div class="column is-full">
        <div class="columns">
          <div class="column is-half">
            <H3> DNS records </H3>
            <DnsRecords :dnsRecords="getDomainTask.last.value.dnsRecords" />
          </div>
          <div class="column is-half">
            <H3> Live preview </H3>
            <Preview :hostname="getDomainTask.last.value.hostname" />
          </div>
        </div>
      </div>

      <div class="column">
        <H3>
          Recent snapshots
          <Counter :hostname="getDomainTask.last.value.hostname" />
        </H3>

        <Table
          v-if="hasSnapshots()"
          :snapshots="getDomainTask.last.value.snapshots"
        />
        <p v-else>N/A</p>
      </div>

      <div class="column">
        <H3> Whois </H3>
        <pre>{{ getDomainTask.last.value.whois || "N/A" }}</pre>
      </div>
    </div>
  </div>
</template>

<script lang="ts">
import { defineComponent } from "@vue/composition-api";
import { useAsyncTask } from "vue-concurrency";

import { API } from "@/api";
import DnsRecords from "@/components/dns_record/DnsRecords.vue";
import Links from "@/components/link/Links.vue";
import Preview from "@/components/screenshot/Preview.vue";
import Counter from "@/components/snapshot/Counter.vue";
import Table from "@/components/snapshot/TableWithScreenshot.vue";
import Error from "@/components/ui/Error.vue";
import H2 from "@/components/ui/H2.vue";
import H3 from "@/components/ui/H3.vue";
import Loading from "@/components/ui/Loading.vue";
import { DomainInformation } from "@/types";

export default defineComponent({
  name: "Domain",
  components: {
    Counter,
    DnsRecords,
    Error,
    H2,
    H3,
    Links,
    Loading,
    Preview,
    Table,
  },
  setup(_, context) {
    const hostname = context.root.$route.params.hostname;

    const getDomainTask = useAsyncTask<DomainInformation, []>(async () => {
      return API.getDomainInformation(hostname);
    });

    getDomainTask.perform();

    const hasSnapshots = () => {
      return (getDomainTask.last?.value?.snapshots.length || 0) > 0;
    };

    return { getDomainTask, hasSnapshots };
  },
});
</script>
