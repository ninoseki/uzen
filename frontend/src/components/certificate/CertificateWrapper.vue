<template>
  <div>
    <Loading v-if="getCertificateTask.isRunning"></Loading>
    <div
      v-else-if="!getCertificateTask.isError && getCertificateTask.last?.value"
    >
      <CertificateComponent :certificate="getCertificateTask.last.value" />
    </div>
    <NA v-else></NA>
  </div>
</template>

<script lang="ts">
import { defineComponent } from "vue";
import { useAsyncTask } from "vue-concurrency";

import { API } from "@/api";
import CertificateComponent from "@/components/certificate/Certificate.vue";
import NA from "@/components/ui/NA.vue";
import Loading from "@/components/ui/SimpleLoading.vue";
import { Certificate } from "@/types";

export default defineComponent({
  name: "CertificateWrapper",
  props: {
    id: {
      type: String,
      required: true,
    },
  },
  components: {
    Loading,
    CertificateComponent,
    NA,
  },
  setup(props) {
    const getCertificateTask = useAsyncTask<Certificate, []>(async () => {
      return await API.getCertificate(props.id);
    });

    getCertificateTask.perform();

    return { getCertificateTask };
  },
});
</script>
