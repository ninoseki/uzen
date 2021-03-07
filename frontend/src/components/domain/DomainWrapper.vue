<template>
  <div>
    <Loading v-if="getDomainTask.isRunning"></Loading>
    <Error
      :backToRoute="true"
      :error="getDomainTask.last.error.response.data"
      v-else-if="getDomainTask.isError && getDomainTask.last !== undefined"
    ></Error>

    <Domain
      v-else-if="
        getDomainTask.last && getDomainTask.last.value && !getDomainTask.isError
      "
      :domain="getDomainTask.last.value"
    ></Domain>
  </div>
</template>

<script lang="ts">
import { defineComponent } from "@vue/composition-api";
import { useAsyncTask } from "vue-concurrency";

import { API } from "@/api";
import Domain from "@/components/domain/Domain.vue";
import Error from "@/components/ui/Error.vue";
import Loading from "@/components/ui/Loading.vue";
import { DomainInformation } from "@/types";

export default defineComponent({
  name: "DomainWrapper",
  components: {
    Error,
    Loading,
    Domain,
  },
  setup(_, context) {
    const hostname = context.root.$route.params.hostname;

    const getDomainTask = useAsyncTask<DomainInformation, []>(async () => {
      return API.getDomainInformation(hostname);
    });

    getDomainTask.perform();

    return { getDomainTask };
  },
});
</script>
