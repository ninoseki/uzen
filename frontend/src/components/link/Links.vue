<template>
  <b-dropdown aria-role="list">
    <button class="button is-dark" slot="trigger" slot-scope="{ active }">
      <b-icon pack="fas" icon="search" size="is-small" />
      <span>Lookup</span>
      <b-icon :icon="active ? 'menu-up' : 'menu-down'"></b-icon>
    </button>

    <b-dropdown-item
      v-for="link in selectedLinks"
      :key="link.name"
      aria-role="listitem"
      has-link
    >
      <LinkComponent
        v-if="link.type === 'domain' && hostname"
        :hostname="hostname"
        :link="link"
      />
      <LinkComponent
        v-if="link.type === 'ip_address' && ipAddress"
        :hostname="ipAddress"
        :link="link"
      />
    </b-dropdown-item>
  </b-dropdown>
</template>

<script lang="ts">
import { computed, defineComponent } from "@vue/composition-api";

import LinkComponent from "@/components/link/Link.vue";
import { Links } from "@/links";
import { Link } from "@/types";

export default defineComponent({
  name: "Links",
  components: {
    LinkComponent,
  },
  props: {
    hostname: {
      type: String,
      required: false,
    },
    ipAddress: {
      type: String,
      required: false,
    },
    type: {
      type: String,
      required: false,
    },
  },
  setup(props) {
    const links = Links;
    const selectedLinks = computed((): Link[] => {
      if (props.type === undefined) {
        return links;
      }

      return links.filter((link) => link.type === props.type);
    });

    return { selectedLinks };
  },
});
</script>
