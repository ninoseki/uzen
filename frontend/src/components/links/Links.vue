<template>
  <b-dropdown aria-role="list">
    <button class="button" slot="trigger" slot-scope="{ active }">
      <b-icon pack="fas" icon="search" size="is-small" />
      <span>Lookup</span>
      <b-icon :icon="active ? 'menu-up' : 'menu-down'"></b-icon>
    </button>

    <b-dropdown-item
      v-for="link in selectedLinks"
      v-bind:key="link.name"
      aria-role="listitem"
      has-link
    >
      <LinkComponent
        v-if="link.type === 'domain'"
        v-bind:hostname="hostname"
        v-bind:link="link"
      />
      <LinkComponent
        v-if="link.type === 'ip_address'"
        v-bind:hostname="ipAddress"
        v-bind:link="link"
      />
    </b-dropdown-item>
  </b-dropdown>
</template>

<script lang="ts">
import { Component, Prop, Vue } from "vue-property-decorator";

import LinkComponent from "@/components/links/Link.vue";
import { Links } from "@/links";
import { Link, LinkType } from "@/types";

@Component({
  components: {
    LinkComponent,
  },
})
export default class LinksComponent extends Vue {
  @Prop() private hostname: string | undefined;
  @Prop() private ipAddress: string | undefined;
  @Prop() private type!: LinkType;

  private links = Links;

  get selectedLinks(): Link[] {
    if (this.type === undefined) {
      return this.links;
    }

    return this.links.filter((link) => link.type === this.type);
  }
}
</script>
