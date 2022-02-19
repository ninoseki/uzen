<template>
  <div class="content">
    <article class="message is-info">
      <div class="message-body">
        Connected IP addresses, domains and hashes.
      </div>
    </article>
    <ul v-if="hasIndicators">
      <li v-for="ipAddress in indicators.ipAddresses" :key="ipAddress">
        <router-link
          :to="{
            name: 'IP address',
            params: {
              ipAddress: ipAddress,
            },
          }"
          >{{ ipAddress }}
        </router-link>
      </li>
      <li v-for="hostname in indicators.hostnames" :key="hostname">
        <router-link
          :to="{
            name: 'Domain',
            params: {
              hostname: hostname,
            },
          }"
          >{{ hostname }}
        </router-link>
      </li>
      <li v-for="hash in indicators.hashes" :key="hash">
        <router-link
          target="_blank"
          :to="{
            name: 'File',
            params: { hash: hash },
          }"
          >{{ hash }}
        </router-link>
      </li>
    </ul>
    <NA v-else></NA>
  </div>
</template>

<script lang="ts">
import { computed, defineComponent, PropType } from "vue";

import NA from "@/components/ui/NA.vue";
import { Indicators } from "@/types";

export default defineComponent({
  name: "IndicatorsItem",
  props: {
    indicators: {
      type: Object as PropType<Indicators>,
      required: true,
    },
  },
  components: {
    NA,
  },
  setup(props) {
    const hasIndicators = computed(() => {
      return (
        props.indicators.hostnames.length +
          props.indicators.ipAddresses.length +
          props.indicators.hashes.length !==
        0
      );
    });

    return { hasIndicators };
  },
});
</script>
