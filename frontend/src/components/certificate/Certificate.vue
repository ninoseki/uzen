<template>
  <div>
    <div v-if="certificate">
      <div class="column">
        <H3>X509 fingerprint (SHA256)</H3>
        <router-link
          :to="{
            name: 'Snapshots',
            query: { certificateFingerprint: certificate.id },
          }"
          >{{ certificate.id }}
        </router-link>
      </div>

      <div class="column">
        <H3>Certificate</H3>
        <pre>{{ certificate.content }}</pre>
      </div>
    </div>
    <NA v-else />
  </div>
</template>

<script lang="ts">
import { defineComponent, PropType } from "@vue/composition-api";

import H3 from "@/components/ui/H3.vue";
import NA from "@/components/ui/NA.vue";
import { Certificate } from "@/types/snapshot";

export default defineComponent({
  name: "Certificate",
  components: { H3, NA },
  props: {
    certificate: {
      type: Object as PropType<Certificate>,
      required: false,
    },
  },
});
</script>
