<template>
  <div>
    <Loading v-if="getDomainTask.isRunning"></Loading>
    <Error
      :error="getDomainTask.last.error.response.data"
      v-if="getDomainTask.isError && getDomainTask.last"
    ></Error>

    <Domain
      v-if="getDomainTask.last?.value && !getDomainTask.isError"
      :domain="getDomainTask.last?.value"
    ></Domain>
  </div>
</template>

<script lang="ts">
import { defineComponent } from "vue";
import { useAsyncTask } from "vue-concurrency";
import { useRoute } from "vue-router";

import { API } from "@/api";
import Domain from "@/components/domain/Domain.vue";
import Error from "@/components/ui/SimpleError.vue";
import Loading from "@/components/ui/SimpleLoading.vue";
import { DomainInformation } from "@/types";

export default defineComponent({
  name: "DomainWrapper",
  components: {
    Error,
    Loading,
    Domain,
  },
  setup() {
    const route = useRoute();
    const hostname = route.params.hostname as string;

    const getDomainTask = useAsyncTask<DomainInformation, []>(async () => {
      return API.getDomainInformation(hostname);
    });

    getDomainTask.perform();

    return { getDomainTask };
  },
});
</script>
