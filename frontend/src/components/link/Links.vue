<template>
  <div class="dropdown is-hoverable">
    <div class="dropdown-trigger">
      <button
        class="button is-dark"
        aria-haspopup="true"
        aria-controls="navbar-lookup-menu"
      >
        <span>Lookup</span>
        <span class="icon is-small">
          <i class="fas fa-search" aria-hidden="true"></i>
        </span>
      </button>
    </div>
    <div class="dropdown-menu" id="navbar-lookup-menu" role="menu">
      <div class="dropdown-content">
        <div
          class="dropdown-item"
          v-for="link in selectedLinks"
          :key="link.name"
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
        </div>
      </div>
    </div>
  </div>
</template>

<script lang="ts">
import { computed, defineComponent } from "vue";

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
