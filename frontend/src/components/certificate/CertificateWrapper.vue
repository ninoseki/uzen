<template>
  <div>
    <div v-if="getCertificateTask.isRunning">Loading...</div>
    <div
      v-else-if="
        !getCertificateTask.isError &&
        getCertificateTask.last &&
        getCertificateTask.last.value
      "
    >
      <CertificateComponent
        :certificate="getCertificateTask.last.value"
        v-if="getCertificateTask.last.value"
      />
    </div>
    <NA v-else></NA>
  </div>
</template>

<script lang="ts">
import { defineComponent } from "@vue/composition-api";
import { useAsyncTask } from "vue-concurrency";

import { API } from "@/api";
import CertificateComponent from "@/components/certificate/Certificate.vue";
import NA from "@/components/ui/NA.vue";
import { Certificate } from "@/types";

export default defineComponent({
  name: "CertificateWrapper",
  props: {
    sha256: {
      type: String,
      required: true,
    },
  },
  components: {
    CertificateComponent,
    NA,
  },
  setup(props) {
    const getCertificateTask = useAsyncTask<Certificate, []>(async () => {
      return await API.getCertificate(props.sha256);
    });

    getCertificateTask.perform();

    return { getCertificateTask };
  },
});
</script>
