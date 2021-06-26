<template>
  <div>
    <div v-if="whois">
      <div class="column">
        <H3>Information</H3>
        <table class="table is-completely-borderless">
          <tbody>
            <tr>
              <th>Created</th>
              <td>{{ whois.created || "N/A" }}</td>
            </tr>
            <tr>
              <th>Updated</th>
              <td>{{ whois.updated || "N/A" }}</td>
            </tr>
            <tr>
              <th>Expires</th>
              <td>{{ whois.expires || "N/A" }}</td>
            </tr>
            <tr>
              <th>Registrar</th>
              <td>{{ whois.registrar || "N/A" }}</td>
            </tr>
            <tr>
              <th>Registrant Organization</th>
              <td>{{ whois.registrantOrganization || "N/A" }}</td>
            </tr>
            <tr>
              <th>Registrant Name</th>
              <td>{{ whois.registrantName || "N/A" }}</td>
            </tr>
          </tbody>
        </table>
      </div>

      <div class="column">
        <H3>Raw</H3>
        <pre>{{ whois.content }}</pre>
      </div>
    </div>
    <NA v-else />
  </div>
</template>

<script lang="ts">
import { defineComponent, PropType } from "@vue/composition-api";

import H3 from "@/components/ui/H3.vue";
import NA from "@/components/ui/NA.vue";
import { Whois } from "@/types/snapshot";

export default defineComponent({
  name: "Whois",
  props: {
    whois: {
      type: Object as PropType<Whois>,
      required: false,
    },
  },
  components: {
    H3,
    NA,
  },
});
</script>
