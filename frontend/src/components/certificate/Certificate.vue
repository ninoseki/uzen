<template>
  <div>
    <div v-if="certificate">
      <div class="column">
        <H3>Information</H3>
        <table class="table is-fullwidth">
          <tbody>
            <tr>
              <th>X509 fingerprint (SHA256)</th>
              <td>
                <router-link
                  :to="{
                    name: 'Snapshots',
                    query: { certificateFingerprint: certificate.id },
                  }"
                  >{{ certificate.id }}
                </router-link>
              </td>
            </tr>
            <tr>
              <th>Subject</th>
              <td>{{ certificate.subject }}</td>
            </tr>
            <tr>
              <th>Issuer</th>
              <td>{{ certificate.issuer }}</td>
            </tr>
            <tr>
              <th>Not After</th>
              <td>{{ certificate.notAfter || "N/A" }}</td>
            </tr>
            <tr>
              <th>Not Before</th>
              <td>{{ certificate.notBefore || "N/A" }}</td>
            </tr>
          </tbody>
        </table>
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
