<template>
  <div class="buttons">
    <b-button v-for="link in links" v-bind:key="link.baseURL">
      <Detail
        v-bind:hostname="snapshot.hostname"
        v-bind:ip_address="snapshot.ip_address"
        v-bind:link="link"
      />
    </b-button>
  </div>
</template>

<script lang="ts">
import { Component, Vue, Prop } from "vue-property-decorator";

import Link from "@/components/links/Link.vue";
import { Links } from "@/links";
import { Snapshot } from "@/types";

@Component({
  components: {
    Link
  }
})
export default class LinksComponent extends Vue {
  @Prop() private snapshot!: Snapshot;
  private links = Links;
}
</script>
