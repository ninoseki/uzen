<template>
  <div>
    <pre v-if="hasCertificate">{{ certificate }}</pre>
    <NA v-else />
  </div>
</template>

<script lang="ts">
import { Component, Prop, Vue } from "vue-property-decorator";

import NA from "@/components/ui/NA.vue";

@Component({
  components: {
    NA,
  },
})
export default class Certificate extends Vue {
  @Prop() private certificate!: string | null;

  get hasCertificate(): boolean {
    return this.certificate !== null;
  }
}
</script>
