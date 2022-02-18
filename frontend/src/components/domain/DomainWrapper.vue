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
import { defineComponent, onMounted } from "vue";
import { useRoute } from "vue-router";

import Domain from "@/components/domain/Domain.vue";
import Error from "@/components/ui/SimpleError.vue";
import Loading from "@/components/ui/SimpleLoading.vue";
import { generateGetDomainTask } from "@/api-helper";

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

    const getDomainTask = generateGetDomainTask();

    onMounted(async () => {
      await getDomainTask.perform(hostname);
    });

    return { getDomainTask };
  },
});
</script>
