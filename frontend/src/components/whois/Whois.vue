<template>
  <div>
    <pre v-if="hasWhois">{{ whois }}</pre>
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
export default class Whois extends Vue {
  @Prop() private whois!: string | null;

  get hasWhois(): boolean {
    return this.whois !== null;
  }
}
</script>
